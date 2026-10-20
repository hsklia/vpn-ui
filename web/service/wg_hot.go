package service

import (
	"errors"
	"fmt"

	awgctrl "github.com/Jipok/wgctrl-go"
	awgtypes "github.com/Jipok/wgctrl-go/wgtypes"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Never change server key, listener, obfuscation or existing peer sessions on a hot add.
func checkHotWireguardDevice(cl *wgctrl.Client, iface, privateKey string, port int) error {
	priv, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return fmt.Errorf("invalid persisted server key: %w", err)
	}
	dev, err := cl.Device(iface)
	if err != nil {
		return fmt.Errorf("live interface unavailable: %w", err)
	}
	if dev.PrivateKey != priv || dev.ListenPort != port {
		return errors.New("live interface differs from persisted server key or listen port")
	}
	return nil
}

func kernelHotPeerOps(live []wgtypes.Peer, desired []wgtypes.PeerConfig) ([]wgtypes.PeerConfig, error) {
	if len(desired) == 0 {
		return nil, errors.New("no enabled peers were generated for the addressed account")
	}
	var ops []wgtypes.PeerConfig
	for _, want := range desired {
		exists := false
		for _, old := range live {
			if old.PublicKey == want.PublicKey {
				var psk wgtypes.Key
				if want.PresharedKey != nil {
					psk = *want.PresharedKey
				}
				if allowedIPsKey(old.AllowedIPs) != allowedIPsKey(want.AllowedIPs) || old.PresharedKey != psk {
					return nil, errors.New("persisted peer conflicts with live address or preshared key")
				}
				exists = true
				continue
			}
			for _, a := range want.AllowedIPs {
				for _, b := range old.AllowedIPs {
					if a.Contains(b.IP) || b.Contains(a.IP) {
						return nil, errors.New("new peer address overlaps a live peer")
					}
				}
			}
		}
		if !exists {
			ops = append(ops, want)
		}
	}
	return ops, nil
}

func applyKernelHotPeers(cl *wgctrl.Client, iface string, desired []wgtypes.PeerConfig) error {
	dev, err := cl.Device(iface)
	if err != nil {
		return err
	}
	ops, err := kernelHotPeerOps(dev.Peers, desired)
	if err != nil {
		return err
	}
	if len(ops) == 0 {
		return nil
	}
	return cl.ConfigureDevice(iface, wgtypes.Config{ReplacePeers: false, Peers: ops})
}

func saveHotKeys(ib *model.Inbound, original string) error {
	result := database.GetDB().Model(ib).Where("settings = ?", original).Update("settings", ib.Settings)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return errors.New("inbound changed concurrently; retry hot provisioning")
	}
	return nil
}

func (s *WgcService) ApplyInboundHot(ib *model.Inbound, email string) error {
	settings, err := s.parseSettings(ib)
	if err != nil {
		return err
	}
	cl, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer cl.Close()
	if err := checkHotWireguardDevice(cl, wgIfaceName(ib.Id), settings.ServerPrivKey, ib.Port); err != nil {
		return err
	}
	original := ib.Settings
	if changed, err := s.ReconcileKeys(ib); err != nil {
		return err
	} else if changed {
		if err := saveHotKeys(ib, original); err != nil {
			return err
		}
	}
	settings, err = s.parseSettings(ib)
	if err != nil {
		return err
	}
	settings.Clients = hotWgcClients(settings.Clients, email)
	if err := applyKernelHotPeers(cl, wgIfaceName(ib.Id), s.buildPeers(ib, settings, s.disabledEmails())); err != nil {
		return err
	}
	return s.SetupRouting()
}

func (s *AwgService) ApplyInboundHot(ib *model.Inbound, email string) error {
	settings, err := s.parseSettings(ib)
	if err != nil {
		return err
	}
	cl, err := awgctrl.New()
	if err != nil {
		return err
	}
	defer cl.Close()
	serverKey, err := awgtypes.ParseKey(settings.ServerPrivKey)
	if err != nil {
		return err
	}
	live, err := cl.Device(awgIfaceName(ib.Id))
	if err != nil {
		return err
	}
	if live.PrivateKey != serverKey || live.ListenPort != ib.Port {
		return errors.New("live AmneziaWG interface differs from persisted key or port")
	}
	original := ib.Settings
	if changed, err := s.reconcileKeysHot(ib); err != nil {
		return err
	} else if changed {
		if err := saveHotKeys(ib, original); err != nil {
			return err
		}
	}
	settings, err = s.parseSettings(ib)
	if err != nil {
		return err
	}
	settings.Clients = hotAwgClients(settings.Clients, email)
	// Reuse the pure collision/idempotency plan, but drive AWG's own netlink API.
	var existing []wgtypes.Peer
	for _, peer := range live.Peers {
		existing = append(existing, wgtypes.Peer{PublicKey: wgtypes.Key(peer.PublicKey), PresharedKey: wgtypes.Key(peer.PresharedKey), AllowedIPs: peer.AllowedIPs})
	}
	var desired []wgtypes.PeerConfig
	for _, peer := range s.buildPeers(ib, settings, s.disabledEmails()) {
		item := wgtypes.PeerConfig{PublicKey: wgtypes.Key(peer.PublicKey), ReplaceAllowedIPs: true, AllowedIPs: peer.AllowedIPs}
		if peer.PresharedKey != nil {
			key := wgtypes.Key(*peer.PresharedKey)
			item.PresharedKey = &key
		}
		desired = append(desired, item)
	}
	ops, err := kernelHotPeerOps(existing, desired)
	if err != nil {
		return err
	}
	if len(ops) > 0 {
		var additions []awgtypes.PeerConfig
		for _, peer := range ops {
			item := awgtypes.PeerConfig{PublicKey: awgtypes.Key(peer.PublicKey), ReplaceAllowedIPs: true, AllowedIPs: peer.AllowedIPs}
			if peer.PresharedKey != nil {
				key := awgtypes.Key(*peer.PresharedKey)
				item.PresharedKey = &key
			}
			additions = append(additions, item)
		}
		if err := cl.ConfigureDevice(awgIfaceName(ib.Id), awgtypes.Config{ReplacePeers: false, Peers: additions}); err != nil {
			return err
		}
	}
	return s.SetupRouting()
}

// Unstamped legacy accounts use their original list position as the pool slot.
// Preserve that position when narrowing the live apply to one account.
func hotWgcClients(clients []wgcClient, email string) []wgcClient {
	var selected []wgcClient
	for index, client := range clients {
		if !sameEmail(client.Email, email) {
			continue
		}
		if client.Slot == nil {
			slot := index
			client.Slot = &slot
		}
		selected = append(selected, client)
	}
	return selected
}

func hotAwgClients(clients []awgClient, email string) []awgClient {
	var selected []awgClient
	for index, client := range clients {
		if !sameEmail(client.Email, email) {
			continue
		}
		if client.Slot == nil {
			slot := index
			client.Slot = &slot
		}
		selected = append(selected, client)
	}
	return selected
}

// Hot peer additions cannot change the device's obfuscation parameters. A normal
// full reconcile is required to initialize missing server headers separately.
func (s *AwgService) reconcileKeysHot(ib *model.Inbound) (bool, error) {
	before, err := s.parseSettings(ib)
	if err != nil {
		return false, err
	}
	original := ib.Settings
	changed, err := s.ReconcileKeys(ib)
	if err != nil {
		ib.Settings = original
		return false, err
	}
	after, err := s.parseSettings(ib)
	if err != nil {
		ib.Settings = original
		return false, err
	}
	if before.resolveObfs().sig() != after.resolveObfs().sig() {
		ib.Settings = original
		return false, errors.New("hot addition cannot initialize or change AmneziaWG server obfuscation")
	}
	return changed, nil
}
