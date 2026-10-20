package service

import (
	"encoding/json"
	"errors"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHotPeerPreservesSettingsAndRejectsCollisions(t *testing.T) {
	settings := `{"secretKey":"server","unknown":{"preserve":true},"clients":[],"peers":[{"email":"old","publicKey":"old-key","privateKey":"old-secret","allowedIPs":["10.1.0.2/32"]}]}`
	peer := json.RawMessage(`{"email":"new","publicKey":"new-key","privateKey":"new-secret","allowedIPs":["10.1.0.3/32"]}`)
	got, _, err := mergeHotPeer(settings, peer)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal([]byte(got), &raw)
	if string(raw["unknown"]) != `{"preserve":true}` || string(raw["secretKey"]) != `"server"` {
		t.Fatalf("settings lost: %s", got)
	}
	retry, _, err := mergeHotPeer(got, peer)
	if err != nil || retry != got {
		t.Fatalf("retry changed settings: %v", err)
	}
	for _, bad := range []string{
		`{"email":"new","publicKey":"changed","allowedIPs":["10.1.0.3/32"]}`,
		`{"email":"other","publicKey":"new-key","allowedIPs":["10.1.0.3/32"]}`,
		`{"email":"other","publicKey":"other-key","allowedIPs":["10.1.0.2/32"]}`,
		`{"email":"other","publicKey":"other-key","allowedIPs":["10.1.0.0/24"]}`,
	} {
		if _, _, err := mergeHotPeer(got, json.RawMessage(bad)); err == nil {
			t.Errorf("collision accepted: %s", bad)
		}
	}
}
func TestHotKernelPeerPlanOnlyAddsNewPeers(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	newKey, _ := wgtypes.GenerateKey()
	_, oldIP, _ := net.ParseCIDR("10.0.0.2/32")
	_, newIP, _ := net.ParseCIDR("10.0.0.3/32")
	live := []wgtypes.Peer{{PublicKey: key, AllowedIPs: []net.IPNet{*oldIP}}}
	ops, err := kernelHotPeerOps(live, []wgtypes.PeerConfig{{PublicKey: newKey, AllowedIPs: []net.IPNet{*newIP}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0].Remove || ops[0].PublicKey != newKey {
		t.Fatalf("bad operations: %+v", ops)
	}
	ops, err = kernelHotPeerOps(live, []wgtypes.PeerConfig{{PublicKey: key, AllowedIPs: []net.IPNet{*oldIP}}})
	if err != nil || len(ops) != 0 {
		t.Fatalf("retry touched old peer: %v %+v", err, ops)
	}
	if _, err := kernelHotPeerOps(live, []wgtypes.PeerConfig{{PublicKey: newKey, AllowedIPs: []net.IPNet{*oldIP}}}); err == nil {
		t.Fatal("address collision accepted")
	}
	if _, err := kernelHotPeerOps(live, []wgtypes.PeerConfig{{PublicKey: key, AllowedIPs: []net.IPNet{*newIP}}}); err == nil {
		t.Fatal("live peer address changed")
	}
}
func TestHotClientFailedApplyPersistsOnceWithoutRestart(t *testing.T) {
	svc := newInboundDB(t)
	ib := seedTaggedInbound(t, model.VLESS, 19001, nil)
	// seedTaggedInbound writes clients:null for nil; the ordinary add path expects an array.
	ib.Settings = `{"clients":[]}`
	database.GetDB().Save(ib)
	oldProcess := p
	p = nil
	defer func() { p = oldProcess }()
	isNeedXrayRestart.Store(false)
	data := addClientPayload(t, ib.Id, map[string]any{"email": "client-u1-s2-i3", "id": "9f1c1e2a-0000-4000-8000-abcdefabcdef", "enable": true})
	for i := 0; i < 2; i++ {
		if err := svc.AddInboundClientHot(data); err == nil {
			t.Fatal("missing live core acknowledged")
		}
	}
	stored, err := svc.GetInbound(ib.Id)
	if err != nil {
		t.Fatal(err)
	}
	clients, err := svc.GetClients(stored)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 {
		t.Fatalf("retry duplicated account: %d", len(clients))
	}
	if isNeedXrayRestart.Load() {
		t.Fatal("failed hot apply requested restart")
	}
}
func TestHotRoutingServiceAddedToStoredTemplateOnce(t *testing.T) {
	config := &xray.Config{API: []byte(`{"tag":"api","services":["HandlerService","StatsService"]}`)}
	if err := enableHotRoutingAPI(config); err != nil {
		t.Fatal(err)
	}
	first := string(config.API)
	if err := enableHotRoutingAPI(config); err != nil {
		t.Fatal(err)
	}
	if first != string(config.API) {
		t.Fatal("API service duplicated")
	}
	var api struct {
		Services []string `json:"services"`
	}
	json.Unmarshal(config.API, &api)
	if len(api.Services) != 3 || api.Services[2] != "RoutingService" {
		t.Fatalf("missing RoutingService: %s", config.API)
	}
}

func TestHotWireguardKeyMirrorSurvivesAccountProjection(t *testing.T) {
	for _, protocol := range []model.Protocol{model.WGC, model.AWG} {
		t.Run(string(protocol), func(t *testing.T) {
			newInboundDB(t)
			ib := seedTaggedInbound(t, protocol, 19003, []map[string]any{{"email": "hot-wg-account", "id": "hot-wg-account", "enable": true}})
			var accounts AccountService
			if err := accounts.SyncInboundAccounts(database.GetDB(), ib.Id); err != nil {
				t.Fatal(err)
			}
			var err error
			if protocol == model.WGC {
				_, err = (&WgcService{}).ReconcileKeys(ib)
			} else {
				_, err = (&AwgService{}).ReconcileKeys(ib)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := database.GetDB().Model(ib).Update("settings", ib.Settings).Error; err != nil {
				t.Fatal(err)
			}
			if err := accounts.SyncInboundAccounts(database.GetDB(), ib.Id); err != nil {
				t.Fatal(err)
			}
			var membership model.AccountInbound
			if err := database.GetDB().Where("inbound_id = ?", ib.Id).First(&membership).Error; err != nil {
				t.Fatal(err)
			}
			var extra map[string]json.RawMessage
			if err := json.Unmarshal([]byte(membership.Extra), &extra); err != nil {
				t.Fatal(err)
			}
			if len(extra["devices"]) == 0 || len(extra["privKey"]) == 0 {
				t.Fatal("minted keys did not reach membership snapshot")
			}
			if _, err := accounts.ProjectAccount(database.GetDB(), membership.AccountId); err != nil {
				t.Fatal(err)
			}
			stored, err := (&InboundService{}).GetInbound(ib.Id)
			if err != nil {
				t.Fatal(err)
			}
			var before, after struct {
				Clients []map[string]json.RawMessage `json:"clients"`
			}
			json.Unmarshal([]byte(ib.Settings), &before)
			json.Unmarshal([]byte(stored.Settings), &after)
			var beforeDevices, afterDevices any
			json.Unmarshal(before.Clients[0]["devices"], &beforeDevices)
			json.Unmarshal(after.Clients[0]["devices"], &afterDevices)
			if !reflect.DeepEqual(beforeDevices, afterDevices) {
				t.Fatal("projection rotated minted device keys")
			}
		})
	}
}

func TestHotPeerCannotClaimServerAddress(t *testing.T) {
	addresses := []any{"10.0.0.5/24"}
	if err := hotPeerAvoidServerAddresses(addresses, []string{"10.0.0.5/32"}); err == nil {
		t.Fatal("server host assigned to peer")
	}
	if err := hotPeerAvoidServerAddresses(addresses, []string{"10.0.0.0/29"}); err == nil {
		t.Fatal("peer prefix encompasses server")
	}
	if err := hotPeerAvoidServerAddresses(addresses, []string{"10.0.0.6/32"}); err != nil {
		t.Fatal(err)
	}
}

func TestHotLegacyWireguardAccountKeepsOriginalPoolSlot(t *testing.T) {
	wgc := []wgcClient{{Email: "first"}, {Email: "target"}, {Email: "third"}}
	awg := []awgClient{{Email: "first"}, {Email: "target"}, {Email: "third"}}
	selectedWgc := hotWgcClients(wgc, "target")
	selectedAwg := hotAwgClients(awg, "target")
	if len(selectedWgc) != 1 || selectedWgc[0].Slot == nil || *selectedWgc[0].Slot != 1 {
		t.Fatal("WG-C legacy pool slot moved")
	}
	if len(selectedAwg) != 1 || selectedAwg[0].Slot == nil || *selectedAwg[0].Slot != 1 {
		t.Fatal("AWG legacy pool slot moved")
	}
	if wgc[1].Slot != nil || awg[1].Slot != nil {
		t.Fatal("hot apply mutated legacy settings")
	}
	fixed := 7
	wgc[1].Slot = &fixed
	awg[1].Slot = &fixed
	if *hotWgcClients(wgc, "target")[0].Slot != fixed || *hotAwgClients(awg, "target")[0].Slot != fixed {
		t.Fatal("persisted pool slot overwritten")
	}
}

func TestHotRetryCannotReviveExpiredOrDepletedClient(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		row          xray.ClientTraffic
	}{
		{"traffic-disabled", "disabled", xray.ClientTraffic{Enable: false}},
		{"expired", "expired", xray.ClientTraffic{Enable: true, ExpiryTime: time.Now().UnixMilli() - 1}},
		{"quota-exhausted", "quota", xray.ClientTraffic{Enable: true, Total: 100, Up: 40, Down: 60}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newInboundDB(t)
			ib := seedTaggedInbound(t, model.VLESS, 19004, []map[string]any{{"email": "blocked-player", "id": "9f1c1e2a-0000-4000-8000-abcdefabcdef", "enable": true}})
			row := tc.row
			row.InboundId = ib.Id
			row.Email = "blocked-player"
			if err := database.GetDB().Create(&row).Error; err != nil {
				t.Fatal(err)
			}
			request := addClientPayload(t, ib.Id, map[string]any{"email": "blocked-player", "id": "9f1c1e2a-0000-4000-8000-abcdefabcdef", "enable": true})
			err := svc.AddInboundClientHot(request)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("revoked account reached live apply: %v", err)
			}
			stored, err := svc.GetInbound(ib.Id)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Settings != ib.Settings {
				t.Fatal("rejected retry mutated settings")
			}
			var count int64
			database.GetDB().Model(&model.AccountInbound{}).Count(&count)
			if count != 0 {
				t.Fatal("rejected retry mutated membership state")
			}
		})
	}
}
func TestHotInboundEligibilityChecksUnsweptLimits(t *testing.T) {
	for _, ib := range []*model.Inbound{{Enable: false}, {Enable: true, ExpiryTime: time.Now().UnixMilli() - 1}, {Enable: true, Total: 100, Up: 50, Down: 50}} {
		if err := hotInboundEligible(ib); err == nil {
			t.Fatal("disabled, expired or exhausted inbound admitted")
		}
	}
	if err := hotInboundEligible(&model.Inbound{Enable: true}); err != nil {
		t.Fatal(err)
	}
}
func TestHotVlessUserInheritsInboundVisionAndTestseed(t *testing.T) {
	ib := &model.Inbound{Protocol: model.VLESS, Settings: `{"flow":"xtls-rprx-vision","testseed":[1,2,3,4]}`, StreamSettings: `{"network":"tcp","security":"reality"}`}
	fields, err := hotAPIClientFields(ib, &model.Client{Email: "vision-user", ID: "9f1c1e2a-0000-4000-8000-abcdefabcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if fields["flow"] != "xtls-rprx-vision" {
		t.Fatal("live user lost inbound Vision flow")
	}
	if seed, ok := fields["testseed"].([]any); !ok || len(seed) != 4 {
		t.Fatal("live user lost inherited testseed")
	}
}

func TestHotAwgKeyReconcileCannotChangeServerObfuscation(t *testing.T) {
	key, _ := wgtypes.GeneratePrivateKey()
	settings, _ := json.Marshal(map[string]any{"serverPrivKey": key.String(), "serverPubKey": key.PublicKey().String(), "clients": []any{}})
	ib := &model.Inbound{Protocol: model.AWG, Settings: string(settings)}
	var svc AwgService
	original := ib.Settings
	if _, err := svc.reconcileKeysHot(ib); err == nil {
		t.Fatal("hot addition minted server headers without applying them")
	}
	if ib.Settings != original {
		t.Fatal("rejected hot reconcile changed persisted candidate")
	}
	if _, err := svc.ReconcileKeys(ib); err != nil {
		t.Fatal(err)
	}
	initialized := ib.Settings
	if _, err := svc.reconcileKeysHot(ib); err != nil {
		t.Fatal(err)
	}
	if ib.Settings != initialized {
		t.Fatal("initialized server obfuscation changed")
	}
}

type hotRemovalRecorder struct {
	tag, email string
	calls      int
}

func (r *hotRemovalRecorder) RemoveUser(tag, email string) error {
	r.tag = tag
	r.email = email
	r.calls++
	return nil
}

func TestHotNativeRecheckRevokesOnlyAddressedUserAfterConcurrentSweep(t *testing.T) {
	svc := newInboundDB(t)
	ib := seedTaggedInbound(t, model.VLESS, 19005, []map[string]any{{"email": "racing-player", "id": "9f1c1e2a-0000-4000-8000-abcdefabcdef", "enable": true}})
	row := xray.ClientTraffic{Email: "racing-player", InboundId: ib.Id, Enable: true}
	if err := database.GetDB().Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.hotClientEligible(row.Email); err != nil {
		t.Fatal(err)
	}
	// The initial check passed; the quota sweep commits while live apply runs.
	if err := database.GetDB().Model(&row).Update("enable", false).Error; err != nil {
		t.Fatal(err)
	}
	remover := &hotRemovalRecorder{}
	err := svc.recheckHotNativeEligibility(remover, ib.Id, ib.Tag, row.Email)
	if !errors.Is(err, errHotAdmissionIneligible) {
		t.Fatalf("revocation was not surfaced: %v", err)
	}
	if remover.calls != 1 || remover.tag != ib.Tag || remover.email != row.Email {
		t.Fatalf("cleanup targeted wrong user: %+v", remover)
	}
	// A transient lookup failure must not disconnect any live user.
	if err := database.GetDB().Migrator().DropTable(&xray.ClientTraffic{}); err != nil {
		t.Fatal(err)
	}
	remover = &hotRemovalRecorder{}
	err = svc.recheckHotNativeEligibility(remover, ib.Id, ib.Tag, row.Email)
	if err == nil || errors.Is(err, errHotAdmissionIneligible) || remover.calls != 0 {
		t.Fatalf("query failure removed live user: %v, %+v", err, remover)
	}
}

func TestHotShadowsocks2022UnsupportedMultiuserMethodRejectedBeforePersistence(t *testing.T) {
	svc := newInboundDB(t)
	ib := seedTaggedInbound(t, model.Shadowsocks, 19006, nil)
	ib.Settings = `{"method":"2022-blake3-chacha20-poly1305","password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","clients":[]}`
	if err := database.GetDB().Save(ib).Error; err != nil {
		t.Fatal(err)
	}
	request := addClientPayload(t, ib.Id, map[string]any{"email": "unsupported-ss2022", "password": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=", "enable": true})
	err := svc.AddInboundClientHot(request)
	if err == nil || !strings.Contains(err.Error(), "multi-user hot addition supports only") {
		t.Fatalf("unsupported multi-user method was not rejected: %v", err)
	}
	stored, err := svc.GetInbound(ib.Id)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Settings != ib.Settings {
		t.Fatal("unsupported hot addition corrupted restart configuration")
	}
	var count int64
	database.GetDB().Model(&xray.ClientTraffic{}).Where("email = ?", "unsupported-ss2022").Count(&count)
	if count != 0 {
		t.Fatal("unsupported hot addition persisted an account")
	}
}
