package service

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// Serialize the read/append/write and live apply, including retry after an
// interrupted request. Compare-and-swap writes reject concurrent inbound changes.
var hotAddLock sync.Mutex

var errHotAdmissionIneligible = errors.New("hot admission is no longer eligible")

func hotClientProtocol(p model.Protocol) bool {
	switch string(p) {
	case "wg-c", "awg", "vmess", "vless", "trojan", "shadowsocks", "hysteria", "hysteria2", "tuic", "anytls", "naive":
		return true
	}
	return false
}

// AddInboundClientHot persists one account, then applies it to the live data
// plane. An apply error intentionally leaves the account persisted for a retry;
// no error path requests a restart or removes/replaces an existing live user.
func (s *InboundService) AddInboundClientHot(data *model.Inbound) error {
	hotAddLock.Lock()
	defer hotAddLock.Unlock()
	// Hold the process lifecycle lock through persistence, live apply and routing,
	// so a concurrent operator restart cannot acknowledge a user on the old core.
	lock.Lock()
	defer lock.Unlock()
	ib, err := s.GetInbound(data.Id)
	if err != nil {
		return err
	}
	if err := hotInboundEligible(ib); err != nil {
		return err
	}
	if !hotClientProtocol(ib.Protocol) {
		return errors.New("inbound does not support hot client addition")
	}
	if ib.Protocol == model.Shadowsocks {
		var settings struct {
			Method string `json:"method"`
		}
		if err := json.Unmarshal([]byte(ib.Settings), &settings); err != nil {
			return err
		}
		if strings.HasPrefix(settings.Method, "2022-") && settings.Method != "2022-blake3-aes-128-gcm" && settings.Method != "2022-blake3-aes-256-gcm" {
			return errors.New("Shadowsocks 2022 multi-user hot addition supports only blake3-aes-128-gcm and blake3-aes-256-gcm")
		}
	}
	var posted struct {
		Clients []map[string]any `json:"clients"`
	}
	if err := json.Unmarshal([]byte(data.Settings), &posted); err != nil {
		return err
	}
	if len(posted.Clients) != 1 {
		return errors.New("hot add requires exactly one client")
	}
	requestedEmail, _ := posted.Clients[0]["email"].(string)
	if err := ValidateClientEmail(requestedEmail); err != nil {
		return err
	}
	var storedShape map[string]json.RawMessage
	if err := json.Unmarshal([]byte(ib.Settings), &storedShape); err != nil {
		return err
	}
	if len(storedShape["clients"]) == 0 || string(storedShape["clients"]) == "null" {
		return errors.New("inbound has no client array")
	}
	clients, err := s.GetClients(ib)
	if err != nil {
		return err
	}
	exists := false
	for _, c := range clients {
		if sameEmail(c.Email, requestedEmail) {
			exists = true
			break
		}
	}
	if !exists {
		if _, err := s.addInboundClient(data, true, nil); err != nil {
			return err
		}
	}
	// Read persisted credentials, never rewrite a retried account from the request.
	ib, err = s.GetInbound(data.Id)
	if err != nil {
		return err
	}
	clients, err = s.GetClients(ib)
	if err != nil {
		return err
	}
	var selected *model.Client
	for i := range clients {
		if sameEmail(clients[i].Email, requestedEmail) {
			selected = &clients[i]
			break
		}
	}
	if selected == nil || !selected.Enable {
		return errors.New("persisted client is absent or disabled")
	}
	if err := s.hotClientEligible(selected.Email); err != nil {
		return err
	}
	var accounts AccountService
	if err := accounts.SyncInboundAccounts(database.GetDB(), ib.Id); err != nil {
		return err
	}
	var nativeAPI *xray.XrayAPI
	switch ib.Protocol {
	case model.WGC:
		var svc WgcService
		applyErr := svc.ApplyInboundHot(ib, requestedEmail)
		// Key reconciliation may have persisted new devices even when the live
		// apply failed. Mirror those keys before returning so later projection
		// cannot restore the pre-key account snapshot.
		if err := accounts.SyncInboundAccounts(database.GetDB(), ib.Id); err != nil {
			return err
		}
		if applyErr != nil {
			return applyErr
		}
	case model.AWG:
		var svc AwgService
		applyErr := svc.ApplyInboundHot(ib, requestedEmail)
		// Key reconciliation may have persisted new devices even when the live
		// apply failed. Mirror those keys before returning so later projection
		// cannot restore the pre-key account snapshot.
		if err := accounts.SyncInboundAccounts(database.GetDB(), ib.Id); err != nil {
			return err
		}
		if applyErr != nil {
			return applyErr
		}
	default:
		fields, err := hotAPIClientFields(ib, selected)
		if err != nil {
			return err
		}
		api := &xray.XrayAPI{}
		nativeAPI = api
		if err := api.Init(p.GetAPIPort()); err != nil {
			return err
		}
		defer api.Close()
		if err := api.EnsureUserHot(string(ib.Protocol), ib.Tag, fields); err != nil {
			return err
		}
		if err := s.recheckHotNativeEligibility(api, ib.Id, ib.Tag, selected.Email); err != nil {
			return err
		}
	}
	if err := (&XrayService{}).reloadRoutingHotLocked(); err != nil {
		return err
	}
	if nativeAPI != nil {
		return s.recheckHotNativeEligibility(nativeAPI, ib.Id, ib.Tag, selected.Email)
	}
	return s.hotClientEligible(selected.Email)
}

// A classic WireGuard peer is node-owned key material, distinct from panel
// clients[]. Preserve the rest of the settings JSON and all existing peers.
type hotWireguardPeer struct {
	Email        string   `json:"email"`
	PublicKey    string   `json:"publicKey"`
	PrivateKey   string   `json:"privateKey,omitempty"`
	PreSharedKey string   `json:"preSharedKey,omitempty"`
	AllowedIPs   []string `json:"allowedIPs"`
	KeepAlive    uint32   `json:"keepAlive,omitempty"`
	Endpoint     string   `json:"endpoint,omitempty"`
}

func hotPeerKeyIdentity(value string) string {
	if raw, err := hex.DecodeString(value); err == nil && len(raw) == 32 {
		return hex.EncodeToString(raw)
	}
	if raw, err := base64.StdEncoding.DecodeString(value); err == nil && len(raw) == 32 {
		return hex.EncodeToString(raw)
	}
	return value
}

func hotPeerAddresses(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		if _, network, err := net.ParseCIDR(value); err == nil {
			value = network.String()
		}
		if !seen[value] {
			out = append(out, value)
			seen[value] = true
		}
	}
	sort.Strings(out)
	return out
}

func mergeHotPeer(settings string, requested json.RawMessage) (string, hotWireguardPeer, error) {
	var want hotWireguardPeer
	if err := json.Unmarshal(requested, &want); err != nil {
		return "", want, err
	}
	if err := ValidateClientEmail(want.Email); err != nil {
		return "", want, err
	}
	if want.Endpoint != "" {
		return "", want, errors.New("live inbound peers must not set an endpoint")
	}
	if want.KeepAlive > 65535 || len(want.AllowedIPs) == 0 {
		return "", want, errors.New("invalid peer keepAlive or allowedIPs")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(settings), &raw); err != nil {
		return "", want, err
	}
	var peers []json.RawMessage
	if p := raw["peers"]; len(p) > 0 {
		if err := json.Unmarshal(p, &peers); err != nil {
			return "", want, err
		}
	}
	for index, oldRaw := range peers {
		var old hotWireguardPeer
		if err := json.Unmarshal(oldRaw, &old); err != nil {
			return "", want, err
		}
		if len(old.AllowedIPs) == 0 {
			return "", want, errors.New("persisted peer has no explicit allowedIPs; cannot safely hot-add")
		}
		if strings.EqualFold(old.Email, want.Email) && old.Email != "" || hotPeerKeyIdentity(old.PublicKey) == hotPeerKeyIdentity(want.PublicKey) {
			// Retrying must never rotate keys or reassign an address. A legacy peer
			// without email can be adopted only with identical key material.
			if hotPeerKeyIdentity(old.PublicKey) != hotPeerKeyIdentity(want.PublicKey) || hotPeerKeyIdentity(old.PreSharedKey) != hotPeerKeyIdentity(want.PreSharedKey) || hotPeerKeyIdentity(old.PrivateKey) != hotPeerKeyIdentity(want.PrivateKey) || !reflect.DeepEqual(hotPeerAddresses(old.AllowedIPs), hotPeerAddresses(want.AllowedIPs)) || old.KeepAlive != want.KeepAlive || old.Email != "" && old.Email != want.Email {
				return "", want, errors.New("peer identity conflicts with existing key material or address")
			}
			if old.Email == "" {
				var oldFields map[string]json.RawMessage
				if err := json.Unmarshal(oldRaw, &oldFields); err != nil {
					return "", want, err
				}
				oldFields["email"], _ = json.Marshal(want.Email)
				peers[index], _ = json.Marshal(oldFields)
				raw["peers"], _ = json.Marshal(peers)
				out, err := json.Marshal(raw)
				return string(out), want, err
			}
			return settings, want, nil
		}
		for _, a := range want.AllowedIPs {
			_, an, err := net.ParseCIDR(a)
			if err != nil {
				return "", want, errors.New("invalid peer CIDR")
			}
			for _, b := range old.AllowedIPs {
				_, bn, err := net.ParseCIDR(b)
				if err != nil {
					return "", want, errors.New("invalid persisted peer CIDR")
				}
				if an.Contains(bn.IP) || bn.Contains(an.IP) {
					return "", want, errors.New("peer address overlaps an existing peer")
				}
			}
		}
	}
	for _, ip := range want.AllowedIPs {
		if _, _, err := net.ParseCIDR(ip); err != nil {
			return "", want, errors.New("invalid peer CIDR")
		}
	}
	peers = append(peers, requested)
	raw["peers"], _ = json.Marshal(peers)
	out, err := json.Marshal(raw)
	return string(out), want, err
}

func (s *InboundService) AddInboundPeerHot(data *model.Inbound) error {
	hotAddLock.Lock()
	defer hotAddLock.Unlock()
	// Hold the process lifecycle lock through persistence, live apply and routing,
	// so a concurrent operator restart cannot acknowledge a user on the old core.
	lock.Lock()
	defer lock.Unlock()
	ib, err := s.GetInbound(data.Id)
	if err != nil {
		return err
	}
	if err := hotInboundEligible(ib); err != nil {
		return err
	}
	if ib.Protocol != model.WireGuard {
		return errors.New("hot peer addition requires a wireguard inbound")
	}
	var posted struct {
		Peers []json.RawMessage `json:"peers"`
	}
	if err := json.Unmarshal([]byte(data.Settings), &posted); err != nil {
		return err
	}
	if len(posted.Peers) != 1 {
		return errors.New("hot add requires exactly one peer")
	}
	// Include managed clients in collision checks: their generated peers are not
	// stored in peers[], but share the same live WireGuard address/key space.
	var effective map[string]any
	if err := json.Unmarshal([]byte(ib.Settings), &effective); err != nil {
		return err
	}
	applyWireguardClients(effective, func(string, bool) bool { return true })
	var requestedPeer hotWireguardPeer
	if err := json.Unmarshal(posted.Peers[0], &requestedPeer); err != nil {
		return err
	}
	if err := hotPeerAvoidServerAddresses(effective["address"], requestedPeer.AllowedIPs); err != nil {
		return err
	}
	effectiveJSON, err := json.Marshal(effective)
	if err != nil {
		return err
	}
	if _, _, err := mergeHotPeer(string(effectiveJSON), posted.Peers[0]); err != nil {
		return err
	}
	settings, peer, err := mergeHotPeer(ib.Settings, posted.Peers[0])
	if err != nil {
		return err
	}
	// Validate all key material before persistence or live mutation.
	if err := xray.ValidateWireguardHotPeer(peer.PublicKey, peer.PreSharedKey, peer.PrivateKey); err != nil {
		return err
	}
	result := database.GetDB().Model(ib).Where("settings = ?", ib.Settings).Update("settings", settings)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return errors.New("inbound changed concurrently; retry hot provisioning")
	}
	api := &xray.XrayAPI{}
	if err := api.Init(p.GetAPIPort()); err != nil {
		return err
	}
	defer api.Close()
	if err := api.EnsureUserHot("wireguard", ib.Tag, map[string]any{
		"email": peer.Email, "publicKey": peer.PublicKey, "preSharedKey": peer.PreSharedKey,
		"allowedIPs": peer.AllowedIPs, "keepAlive": peer.KeepAlive,
	}); err != nil {
		return err
	}
	return (&XrayService{}).reloadRoutingHotLocked()
}

// ReloadRoutingHot uses the bundled fork's CLI so its extended routing schema is
// built by exactly the core that runs it. The private file is removed on all paths.
func (s *XrayService) ReloadRoutingHot() error {
	lock.Lock()
	defer lock.Unlock()
	return s.reloadRoutingHotLocked()
}

func (s *XrayService) reloadRoutingHotLocked() error {
	if !s.IsXrayRunning() || p.GetAPIPort() <= 0 {
		return errors.New("core is not running")
	}
	config, err := s.GetXrayConfig()
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"routing": json.RawMessage(config.RouterConfig)})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "vpn-ui-hot-routing-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, xray.GetBinaryPath(), "api", "adrules", fmt.Sprintf("--server=127.0.0.1:%d", p.GetAPIPort()), "--timeout=5", f.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("hot routing apply failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// A peer must not claim the server's own tunnel address (including a custom host
// inside a configured interface prefix). Only the interface host is reserved.
func hotPeerAvoidServerAddresses(raw any, allowed []string) error {
	addresses := []string{"10.0.0.1", "fd59:7153:2388:b5fd::1"}
	if values, ok := raw.([]any); ok {
		addresses = nil
		for _, value := range values {
			if address, ok := value.(string); ok {
				addresses = append(addresses, address)
			} else {
				return errors.New("invalid server tunnel address")
			}
		}
	}
	for _, address := range addresses {
		ip := net.ParseIP(address)
		if ip == nil {
			if host, _, err := net.ParseCIDR(address); err == nil {
				ip = host
			}
		}
		if ip == nil {
			return errors.New("invalid server tunnel address")
		}
		for _, value := range allowed {
			_, network, err := net.ParseCIDR(value)
			if err != nil {
				return errors.New("invalid peer CIDR")
			}
			if network.Contains(ip) {
				return errors.New("peer address overlaps the server tunnel address")
			}
		}
	}
	return nil
}

// Traffic is the authoritative account-wide admission state. Checking the raw
// expiry/quota too closes the interval before the next invalid-client sweep.
func (s *InboundService) hotClientEligible(email string) error {
	var traffic xray.ClientTraffic
	if err := database.GetDB().Where("LOWER(TRIM(email)) = ?", accountKey(email)).First(&traffic).Error; err != nil {
		return err
	}
	if !traffic.Enable {
		return fmt.Errorf("%w: account traffic state is disabled", errHotAdmissionIneligible)
	}
	if traffic.ExpiryTime > 0 && traffic.ExpiryTime <= time.Now().UnixMilli() {
		return fmt.Errorf("%w: account has expired", errHotAdmissionIneligible)
	}
	if traffic.Total > 0 && (traffic.Up >= traffic.Total || traffic.Down >= traffic.Total-traffic.Up) {
		return fmt.Errorf("%w: account quota is exhausted", errHotAdmissionIneligible)
	}
	return nil
}

func hotAPIClientFields(ib *model.Inbound, target *model.Client) (map[string]any, error) {
	var settings map[string]any
	if err := json.Unmarshal([]byte(ib.Settings), &settings); err != nil {
		return nil, err
	}
	cipher, _ := settings["method"].(string)
	flow := target.Flow
	if ib.Protocol == model.VLESS {
		if flow == "" {
			flow = inboundVlessFlow(ib)
		}
		if flow == "xtls-rprx-vision-udp443" {
			flow = "xtls-rprx-vision"
		}
	}
	fields := map[string]any{"email": target.Email, "id": target.ID, "auth": target.Auth,
		"security": target.Security, "flow": flow, "password": target.Password,
		"username": target.Username, "cipher": cipher}
	if ib.Protocol == model.VLESS {
		fields["testseed"] = settings["testseed"]
	}
	return fields, nil
}

func hotInboundEligible(ib *model.Inbound) error {
	if !ib.Enable {
		return fmt.Errorf("%w: inbound is disabled", errHotAdmissionIneligible)
	}
	if ib.ExpiryTime > 0 && ib.ExpiryTime <= time.Now().UnixMilli() {
		return fmt.Errorf("%w: inbound has expired", errHotAdmissionIneligible)
	}
	if ib.Total > 0 && (ib.Up >= ib.Total || ib.Down >= ib.Total-ib.Up) {
		return fmt.Errorf("%w: inbound quota is exhausted", errHotAdmissionIneligible)
	}
	return nil
}

// The quota sweep can revoke a user between the initial check and the live add.
// Recheck after apply and after routing; only an explicit admission denial removes
// the addressed user. A database/query error returns without touching live users.
// Removing a user that the sweep already removed is an idempotent cleanup.
type hotUserRemover interface{ RemoveUser(string, string) error }

func (s *InboundService) recheckHotNativeEligibility(api hotUserRemover, inboundID int, tag, email string) error {
	ib, err := s.GetInbound(inboundID)
	if err != nil {
		return err
	}
	err = hotInboundEligible(ib)
	if err == nil {
		var membership struct {
			Clients []model.Client `json:"clients"`
		}
		if parseErr := json.Unmarshal([]byte(ib.Settings), &membership); parseErr != nil {
			return parseErr
		}
		found := false
		for _, client := range membership.Clients {
			if sameEmail(client.Email, email) {
				found = client.Enable
				break
			}
		}
		if !found {
			err = fmt.Errorf("%w: addressed membership is absent or disabled", errHotAdmissionIneligible)
		}
	}
	if err == nil {
		err = s.hotClientEligible(email)
	}
	if !errors.Is(err, errHotAdmissionIneligible) {
		return err
	}
	if removeErr := api.RemoveUser(tag, email); removeErr != nil && !strings.Contains(strings.ToLower(removeErr.Error()), "not found") {
		return fmt.Errorf("%w; addressed user revocation cleanup failed: %v", err, removeErr)
	}
	return err
}
