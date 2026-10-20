package service

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// This opt-in test uses the actual bundled core, not a fake HTTP/gRPC server.
// It exercises persisted account -> core user -> routing apply -> working TCP.
func TestHotClientLiveCorePreservesEstablishedConnection(t *testing.T) {
	executable := os.Getenv("VPNUI_HOT_ADD_TEST_BINARY")
	if executable == "" {
		t.Skip("set VPNUI_HOT_ADD_TEST_BINARY to the built patched core")
	}
	svc := newInboundDB(t)
	work := t.TempDir()
	t.Setenv("VPNUI_BIN_FOLDER", filepath.Join(work, "bin"))
	t.Setenv("VPNUI_LOG_FOLDER", filepath.Join(work, "log"))
	if err := os.MkdirAll(filepath.Dir(xray.GetBinaryPath()), 0700); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(xray.GetBinaryPath(), content, 0700); err != nil {
		t.Fatal(err)
	}

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	freePort := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	apiPort, inboundPort := freePort(), freePort()
	const oldID = "9f1c1e2a-0000-4000-8000-abcdefabcdef"
	const newID = "9f1c1e2a-0000-4000-8000-ffffffffffff"
	ib := &model.Inbound{UserId: 1, Tag: "live-vless", Protocol: model.VLESS, Listen: "127.0.0.1", Port: inboundPort, Enable: true,
		Settings:       `{"decryption":"none","clients":[{"id":"` + oldID + `","email":"old-player","enable":true}]}`,
		StreamSettings: `{"network":"tcp","security":"none"}`}
	if err := database.GetDB().Create(ib).Error; err != nil {
		t.Fatal(err)
	}
	serverKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	oldPeerKey, _ := wgtypes.GeneratePrivateKey()
	newPeerKey, _ := wgtypes.GeneratePrivateKey()
	wgSettings, _ := json.Marshal(map[string]any{
		"secretKey": serverKey.String(), "address": []string{"10.222.0.1/32"}, "noKernelTun": true,
		"peers": []map[string]any{{"publicKey": oldPeerKey.PublicKey().String(), "allowedIPs": []string{"10.222.0.2/32"}}},
	})
	wgInbound := &model.Inbound{UserId: 1, Tag: "live-wireguard", Protocol: model.WireGuard, Listen: "127.0.0.1", Port: freePort(), Enable: true, Settings: string(wgSettings)}
	if err := database.GetDB().Create(wgInbound).Error; err != nil {
		t.Fatal(err)
	}
	peerSettings, _ := json.Marshal(map[string]any{"peers": []map[string]any{{
		"email": "new-wireguard-peer", "privateKey": newPeerKey.String(), "publicKey": newPeerKey.PublicKey().String(), "allowedIPs": []string{"10.222.0.3/32"}, "keepAlive": uint32(25),
	}}})
	peerRequest := &model.Inbound{Id: wgInbound.Id, Settings: string(peerSettings)}
	applyClassic := func() {
		if err := svc.AddInboundPeerHot(peerRequest); err != nil {
			t.Fatalf("classic live peer addition: %v", err)
		}
		api := &xray.XrayAPI{}
		if err := api.Init(p.GetAPIPort()); err != nil {
			t.Fatal(err)
		}
		defer api.Close()
		if err := api.EnsureUserHot("wireguard", wgInbound.Tag, map[string]any{"email": "new-wireguard-peer", "publicKey": newPeerKey.PublicKey().String(), "allowedIPs": []string{"10.222.0.3/32"}, "keepAlive": uint32(25)}); err != nil {
			t.Fatalf("live classic peer differs from persisted credentials: %v", err)
		}
	}
	template := fmt.Sprintf(`{"log":{"loglevel":"error"},"api":{"tag":"api","services":["HandlerService","StatsService"]},"inbounds":[{"tag":"api","listen":"127.0.0.1","port":%d,"protocol":"tunnel","settings":{"address":"127.0.0.1"}}],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{"ipsBlocked":[]}},{"tag":"blocked","protocol":"blackhole"}],"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]},"stats":{}}`, apiPort)
	settings := &SettingService{}
	if err := settings.setString("xrayTemplateConfig", template); err != nil {
		t.Fatal(err)
	}
	config, err := (&XrayService{}).GetXrayConfig()
	if err != nil {
		t.Fatal(err)
	}
	p = xray.NewProcess(config)
	original := p
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { original.Stop() })
	deadline := time.Now().Add(8 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(inboundPort)), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("core did not start: %s", p.GetResult())
		}
		time.Sleep(20 * time.Millisecond)
	}
	open := func(id string) net.Conn {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(inboundPort)), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		uuid, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
		if err != nil {
			t.Fatal(err)
		}
		var header bytes.Buffer
		header.WriteByte(0)
		header.Write(uuid)
		header.WriteByte(0)
		header.WriteByte(1)
		binary.Write(&header, binary.BigEndian, uint16(echo.Addr().(*net.TCPAddr).Port))
		header.Write([]byte{1, 127, 0, 0, 1})
		header.WriteString("hello")
		if _, err := conn.Write(header.Bytes()); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 7)
		if _, err := io.ReadFull(conn, response); err != nil {
			t.Fatalf("live VLESS connection failed: %v (core: %s)", err, p.GetResult())
		}
		if !bytes.Equal(response, append([]byte{0, 0}, []byte("hello")...)) {
			t.Fatalf("invalid VLESS response: %x", response)
		}
		return conn
	}
	ping := func(conn net.Conn, n int) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		message := []byte(fmt.Sprintf("still-playing-%02d", n))
		if _, err := conn.Write(message); err != nil {
			t.Fatal(err)
		}
		received := make([]byte, len(message))
		if _, err := io.ReadFull(conn, received); err != nil {
			t.Fatalf("existing TCP session was interrupted: %v", err)
		}
		if !bytes.Equal(received, message) {
			t.Fatal("corrupt echo")
		}
	}
	old := open(oldID)
	defer old.Close()
	ping(old, 0)
	priorFlag := isNeedXrayRestart.Load()
	isNeedXrayRestart.Store(false)
	t.Cleanup(func() { isNeedXrayRestart.Store(priorFlag) })
	posted, _ := json.Marshal(map[string]any{"clients": []map[string]any{{"email": "new-player", "id": newID, "enable": true}}})
	request := &model.Inbound{Id: ib.Id, Settings: string(posted)}
	if err := svc.AddInboundClientHot(request); err != nil {
		t.Fatal(err)
	}
	ping(old, 1)
	added := open(newID)
	defer added.Close()
	ping(added, 2)
	// Repeating a lost-response request must not replace either account.
	if err := svc.AddInboundClientHot(request); err != nil {
		t.Fatal(err)
	}
	ping(old, 3)
	ping(added, 4)
	applyClassic()
	ping(old, 30)
	applyClassic() // identical lost-response retry must not touch the device
	ping(added, 31)

	stored, err := svc.GetInbound(ib.Id)
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := svc.GetClients(stored)
	if err != nil || len(accounts) != 2 {
		t.Fatalf("persisted accounts: %d, %v", len(accounts), err)
	}
	// Core-side rejection must preserve the prior live routing table and both sockets.
	invalid := strings.Replace(template, `"inboundTag":["api"]`, `"inboundTag":["api"],"domain":["regexp:["]`, 1)
	if err := settings.setString("xrayTemplateConfig", invalid); err != nil {
		t.Fatal(err)
	}
	if err := (&XrayService{}).ReloadRoutingHot(); err == nil {
		t.Fatal("invalid routing update was accepted")
	}
	ping(old, 5)
	ping(added, 6)
	fresh := open(newID)
	defer fresh.Close()
	ping(fresh, 7)
	if p != original || !p.IsRunning() || isNeedXrayRestart.Load() {
		t.Fatal("hot addition or failure requested/replaced the core")
	}
	t.Log("real core: account persistence, idempotent retries, old/new TCP traffic and failed-routing survival verified")
	// An intentional staging restart loads all persisted peers/accounts. Re-ensure
	// the classic identity to exercise adoption without rotating its initial key.
	if err := settings.setString("xrayTemplateConfig", template); err != nil {
		t.Fatal(err)
	}
	if err := original.Stop(); err != nil {
		t.Fatal(err)
	}
	config, err = (&XrayService{}).GetXrayConfig()
	if err != nil {
		t.Fatal(err)
	}
	p = xray.NewProcess(config)
	restarted := p
	if err := restarted.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restarted.Stop() })
	deadline = time.Now().Add(8 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(inboundPort)), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("staging restart did not start: %s", p.GetResult())
		}
		time.Sleep(20 * time.Millisecond)
	}
	applyClassic()
	afterRestart := open(newID)
	defer afterRestart.Close()
	ping(afterRestart, 32)
	storedWG, err := svc.GetInbound(wgInbound.Id)
	if err != nil {
		t.Fatal(err)
	}
	var persisted struct {
		Peers []hotWireguardPeer `json:"peers"`
	}
	if err := json.Unmarshal([]byte(storedWG.Settings), &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted.Peers) != 2 || persisted.Peers[1].PrivateKey != newPeerKey.String() {
		t.Fatal("planned restart/retry changed persisted peer keys")
	}
	t.Log("classic peer live application/retry and persistence across an intentional staging restart verified")

}
