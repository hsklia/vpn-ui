package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Opt-in isolated service staging: one actual shared core, real panel persistence
// and hot-admission services, an external runner holding native protocol traffic.
// Full panel login/router/node HTTP startup is deliberately tested separately.
func TestHotMatrixLiveSharedCore(t *testing.T) {
	binaryPath, runner := os.Getenv("VPNUI_HOT_ADD_TEST_BINARY"), os.Getenv("VPNUI_STAGE_NATIVE_RUNNER")
	if binaryPath == "" || runner == "" {
		t.Skip("set VPNUI_HOT_ADD_TEST_BINARY and VPNUI_STAGE_NATIVE_RUNNER")
	}
	svc := newInboundDB(t)
	work := t.TempDir()
	t.Setenv("VPNUI_BIN_FOLDER", filepath.Join(work, "bin"))
	t.Setenv("VPNUI_LOG_FOLDER", filepath.Join(work, "log"))
	if err := os.MkdirAll(filepath.Dir(xray.GetBinaryPath()), 0700); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(xray.GetBinaryPath(), content, 0700); err != nil {
		t.Fatal(err)
	}
	exportDir := os.Getenv("VPNUI_STAGE_EXPORT")
	if exportDir == "" {
		exportDir = filepath.Join(work, "fixture")
	}
	if err := os.MkdirAll(exportDir, 0700); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(exportDir, "server-cert.pem"), filepath.Join(exportDir, "server-key.pem")
	stageCertificate(t, certPath, keyPath)
	tlsStream := func(network string) string {
		stream := map[string]any{"network": network, "security": "tls", "tlsSettings": map[string]any{"serverName": "localhost", "alpn": []string{"h3", "h2", "http/1.1"}, "certificates": []any{map[string]any{"certificateFile": certPath, "keyFile": keyPath}}}}
		if network == "hysteria" {
			stream["hysteriaSettings"] = map[string]any{"version": 2, "udpIdleTimeout": 60}
		}
		body, _ := json.Marshal(stream)
		return string(body)
	}
	freePort := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	apiPort := freePort()
	template := fmt.Sprintf(`{"log":{"loglevel":"warning"},"api":{"tag":"api","services":["HandlerService","StatsService"]},"inbounds":[{"tag":"api","listen":"127.0.0.1","port":%d,"protocol":"tunnel","settings":{"address":"127.0.0.1"}}],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{"ipsBlocked":[],"redirect":"127.0.0.1:0"}},{"tag":"blocked","protocol":"blackhole"}],"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]},"stats":{}}`, apiPort)
	settingsService := &SettingService{}
	if err := settingsService.setString("xrayTemplateConfig", template); err != nil {
		t.Fatal(err)
	}
	tokenData := make([]byte, 24)
	rand.Read(tokenData)
	token := hex.EncodeToString(tokenData)
	manifest := map[string]any{"control_token": token, "protocols": []map[string]any{}}
	type entry struct {
		ib       *model.Inbound
		clients  []map[string]any
		manifest map[string]any
		peer     bool
	}
	entries := map[string]*entry{}
	var ordered []*entry
	addEntry := func(label, protocol, method, stream string) {
		port := freePort()
		serverPassword := ""
		if strings.HasPrefix(method, "2022-") {
			n := 32
			if strings.Contains(method, "128") {
				n = 16
			}
			serverPassword = stagePSK(label+"server", n)
		}
		accounts := make([]map[string]any, 4)
		for generation := 0; generation < 4; generation++ {
			name := fmt.Sprintf("%s-user-%d", label, generation)
			account := map[string]any{"email": name, "enable": true, "id": fmt.Sprintf("9f1c1e2a-%04x-4000-8000-%012x", len(ordered)+1, generation+1), "password": "stage-" + name, "auth": "auth-" + name}
			if strings.HasPrefix(method, "2022-") {
				n := 32
				if strings.Contains(method, "128") {
					n = 16
				}
				account["password"] = stagePSK(name, n)
				account["method"] = ""
			}
			accounts[generation] = account
		}
		inboundSettings := map[string]any{"clients": []any{accounts[0]}}
		switch protocol {
		case "vless":
			inboundSettings["decryption"] = "none"
		case "shadowsocks":
			inboundSettings["method"] = method
			inboundSettings["network"] = "tcp,udp"
			if serverPassword != "" {
				inboundSettings["password"] = serverPassword
			}
		case "hysteria", "hysteria2":
			inboundSettings["version"] = 2
		case "tuic":
			inboundSettings["congestionControl"] = "cubic"
			inboundSettings["heartbeat"] = 10
			inboundSettings["udpTimeout"] = 60
		}
		body, _ := json.Marshal(inboundSettings)
		ib := &model.Inbound{UserId: 1, Tag: "stage-" + label, Protocol: model.Protocol(protocol), Listen: "127.0.0.1", Port: port, Enable: true, Settings: string(body), StreamSettings: stream}
		if err := database.GetDB().Create(ib).Error; err != nil {
			t.Fatal(err)
		}
		persistedClients, err := svc.GetClients(ib)
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.AddClientStat(database.GetDB(), ib.Id, &persistedClients[0]); err != nil {
			t.Fatal(err)
		}
		if err := (&AccountService{}).SyncInboundAccounts(database.GetDB(), ib.Id); err != nil {
			t.Fatal(err)
		}
		view := map[string]any{"label": label, "protocol": protocol, "inbound_id": ib.Id, "server": "127.0.0.1", "port": port, "method": method, "server_password": serverPassword, "old": accounts[0], "new": accounts[1], "additional": accounts[2:], "tls": map[string]any{"server_name": "localhost", "certificate_path": certPath}}
		e := &entry{ib: ib, clients: accounts, manifest: view}
		entries[label] = e
		ordered = append(ordered, e)
	}
	plain := `{"network":"tcp","security":"none"}`
	addEntry("vless", "vless", "", plain)
	addEntry("vmess", "vmess", "", plain)
	addEntry("trojan", "trojan", "", tlsStream("tcp"))
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		addEntry("ss-"+method, "shadowsocks", method, plain)
	}
	addEntry("hysteria2", "hysteria", "", tlsStream("hysteria"))
	addEntry("tuic", "tuic", "", tlsStream("tuic"))
	// A userspace WireGuard observer remains on the same shared core throughout.
	serverKey, _ := wgtypes.GeneratePrivateKey()
	wgPort := freePort()
	wgAccounts := make([]map[string]any, 4)
	for i := range wgAccounts {
		key, _ := wgtypes.GeneratePrivateKey()
		psk, _ := wgtypes.GenerateKey()
		address := fmt.Sprintf("10.250.0.%d/32", i+2)
		wgAccounts[i] = map[string]any{"email": fmt.Sprintf("classic-wg-%d", i), "private_key": key.String(), "address": address, "server_public_key": serverKey.PublicKey().String(), "pre_shared_key": psk.String(), "publicKey": key.PublicKey().String(), "privateKey": key.String(), "preSharedKey": psk.String(), "allowedIPs": []string{address}, "keepAlive": 25}
	}
	wgSettings, _ := json.Marshal(map[string]any{"secretKey": serverKey.String(), "address": []string{"10.250.0.1/32"}, "mtu": 1420, "peers": []any{wgAccounts[0]}})
	wgInbound := &model.Inbound{UserId: 1, Tag: "stage-classic-wireguard", Protocol: model.WireGuard, Listen: "127.0.0.1", Port: wgPort, Enable: true, Settings: string(wgSettings), StreamSettings: plain}
	if err := database.GetDB().Create(wgInbound).Error; err != nil {
		t.Fatal(err)
	}
	wgView := map[string]any{"label": "classic-wireguard", "protocol": "wireguard", "inbound_id": wgInbound.Id, "server": "127.0.0.1", "port": wgPort, "observe_only": false, "echo_address": "198.18.0.1", "old": wgAccounts[0], "new": wgAccounts[1], "additional": wgAccounts[2:]}
	wgEntry := &entry{ib: wgInbound, clients: wgAccounts, manifest: wgView, peer: true}
	entries["classic-wireguard"] = wgEntry
	ordered = append(ordered, wgEntry)
	var initialInbounds []*model.Inbound
	views := make([]map[string]any, 0, len(ordered))
	for _, e := range ordered {
		initialInbounds = append(initialInbounds, e.ib)
		views = append(views, e.manifest)
	}
	manifest["protocols"] = views
	writeJSON := func(path string, value any) {
		body, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeJSON(filepath.Join(exportDir, "inbounds.json"), initialInbounds)
	if err := os.WriteFile(filepath.Join(exportDir, "template.json"), []byte(template), 0600); err != nil {
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
	priorFlag := isNeedXrayRestart.Load()
	isNeedXrayRestart.Store(false)
	t.Cleanup(func() { isNeedXrayRestart.Store(priorFlag) })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlURL := "http://" + listener.Addr().String()
	manifest["control_url"] = controlURL
	manifest["status_url"] = controlURL + "/status"
	manifest["invalid_routing_url"] = controlURL + "/invalid-routing"
	var callsMu sync.Mutex
	calls := map[string]int{}
	mux := http.NewServeMux()
	authorized := func(w http.ResponseWriter, r *http.Request) bool {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}
	reply := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(value)
	}
	mux.HandleFunc("/add", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r) {
			return
		}
		var request struct {
			Label      string `json:"label"`
			Protocol   string `json:"protocol"`
			Generation int    `json:"generation"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		label := request.Label
		if label == "" {
			label = request.Protocol
		}
		e := entries[label]
		if e == nil || request.Generation < 0 || request.Generation > 2 {
			http.Error(w, "unknown fixture account", 400)
			return
		}
		account := e.clients[request.Generation+1]
		field := "clients"
		if e.peer {
			field = "peers"
		}
		body, _ := json.Marshal(map[string]any{field: []any{account}})
		var err error
		if e.peer {
			err = svc.AddInboundPeerHot(&model.Inbound{Id: e.ib.Id, Settings: string(body)})
		} else {
			err = svc.AddInboundClientHot(&model.Inbound{Id: e.ib.Id, Settings: string(body)})
		}
		if err != nil {
			reply(w, map[string]any{"success": false, "msg": err.Error()})
			return
		}
		callsMu.Lock()
		calls[label]++
		callsMu.Unlock()
		reply(w, map[string]any{"success": true, "obj": map[string]any{"applied": true, "noRestart": true}})
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r) {
			return
		}
		lock.Lock()
		stable := p == original && p.IsRunning() && !isNeedXrayRestart.Load()
		lock.Unlock()
		counts := map[string]int{}
		for _, e := range ordered {
			stored, err := svc.GetInbound(e.ib.Id)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if e.peer {
				var raw struct {
					Peers []any `json:"peers"`
				}
				json.Unmarshal([]byte(stored.Settings), &raw)
				counts[e.manifest["label"].(string)] = len(raw.Peers)
			} else {
				clients, _ := svc.GetClients(stored)
				counts[e.manifest["label"].(string)] = len(clients)
			}
		}
		reply(w, map[string]any{"stable": stable, "persisted_counts": counts})
	})
	mux.HandleFunc("/invalid-routing", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r) {
			return
		}
		invalid := strings.Replace(template, `"inboundTag":["api"]`, `"inboundTag":["api"],"domain":["regexp:["]`, 1)
		if err := settingsService.setString("xrayTemplateConfig", invalid); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		applyErr := (&XrayService{}).ReloadRoutingHot()
		restoreErr := settingsService.setString("xrayTemplateConfig", template)
		if applyErr == nil || restoreErr != nil {
			http.Error(w, fmt.Sprintf("invalid route result: apply=%v restore=%v", applyErr, restoreErr), 500)
			return
		}
		reply(w, map[string]any{"success": true, "rejected": true})
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go server.Serve(listener)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		server.Shutdown(ctx)
	})
	manifestPath := filepath.Join(exportDir, "manifest.json")
	writeJSON(manifestPath, manifest)
	t.Logf("initial fixture exported at %s", exportDir)
	cmd := exec.Command("python3", runner)
	cmd.Env = append(os.Environ(), "HOT_STAGE_MANIFEST="+manifestPath, "HOT_STAGE_CONTROL_URL="+controlURL, "HOT_STAGE_CORE_BINARY="+xray.GetBinaryPath())
	output, runErr := cmd.CombinedOutput()
	if err := os.WriteFile(filepath.Join(exportDir, "native-runner.log"), output, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("native runner: %s", output)
	if runErr != nil {
		t.Fatalf("native protocol staging failed: %v (core: %s)", runErr, p.GetResult())
	}
	if p != original || !p.IsRunning() || isNeedXrayRestart.Load() {
		t.Fatal("native matrix replaced/requested restart of shared core")
	}
	callsMu.Lock()
	defer callsMu.Unlock()
	for _, e := range ordered {
		label := e.manifest["label"].(string)
		if calls[label] < 2 {
			t.Fatalf("inbound %s did not receive admission and retry", label)
		}
	}
	t.Logf("shared-core matrix passed: %d native inbounds, one WireGuard inbound, %d hot-admission fixture groups", len(ordered)-1, len(calls))
}

func stagePSK(seed string, size int) string {
	sum := sha256.Sum256([]byte(seed))
	return base64.StdEncoding.EncodeToString(sum[:size])
}
func stageCertificate(t *testing.T, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
}
