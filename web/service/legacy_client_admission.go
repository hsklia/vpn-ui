package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
	"gorm.io/gorm"
)

// LegacyClientAddition keeps the legacy authorization and pricing workflow while
// serializing persistence, membership projection and acknowledged live activation.
// Call Close on every non-nil result from BeginLegacyClientAddition.
type LegacyClientAddition struct {
	user      model.User
	anchor    int
	ids       []int
	emails    []string
	requested map[string]model.Client
	receipt   model.LegacyClientAdmission
	persisted bool
	closed    bool
}

// BeginLegacyClientAddition returns nil for an ordinary legacy request that does
// not address a kernel WireGuard inbound. No mutation or reservation happens here.
func (s *InboundService) BeginLegacyClientAddition(data *model.Inbound, user *model.User, membershipIDs []int, explicit bool) (_ *LegacyClientAddition, err error) {
	if data == nil {
		return nil, errors.New("missing client addition")
	}
	hotAddLock.Lock()
	lock.Lock()
	a := &LegacyClientAddition{anchor: data.Id, requested: map[string]model.Client{}}
	keep := false
	defer func() {
		if !keep {
			a.Close()
		}
	}()
	// The anchor determines the scope even when an explicit empty membership set
	// will move the newly created account off it again.
	scope := legacyAdmissionIDs(append(append([]int{}, membershipIDs...), data.Id))
	var svc InboundService
	inbounds := make(map[int]*model.Inbound, len(scope))
	scoped := false
	for _, id := range scope {
		ib, loadErr := svc.GetInbound(id)
		if loadErr != nil {
			return nil, loadErr
		}
		inbounds[id] = ib
		scoped = scoped || ib.Protocol == model.WGC || ib.Protocol == model.AWG
	}
	if !scoped {
		a.Close()
		return nil, nil
	}
	if user == nil || user.Id <= 0 {
		return nil, errors.New("client addition requires an authenticated caller")
	}
	a.user = *user
	a.ids = legacyAdmissionIDs(membershipIDs)
	if !explicit {
		a.ids = legacyAdmissionIDs(append(a.ids, data.Id))
	}
	for _, ib := range inbounds {
		if !hotClientProtocol(ib.Protocol) {
			return nil, fmt.Errorf("protocol %q cannot join a client addition without restarting the shared core", ib.Protocol)
		}
		if err := legacyAdmissionProtocol(ib); err != nil {
			return nil, err
		}
	}
	canonical, emails, clients, parseErr := legacyAdmissionRequest(data)
	if parseErr != nil {
		return nil, parseErr
	}
	a.emails, a.requested = emails, clients
	identity, marshalErr := json.Marshal(struct {
		UserID      int             `json:"userId"`
		InboundID   int             `json:"inboundId"`
		Settings    json.RawMessage `json:"settings"`
		Memberships []int           `json:"memberships"`
		Explicit    bool            `json:"explicit"`
	}{user.Id, data.Id, canonical, legacyAdmissionIDs(membershipIDs), explicit})
	if marshalErr != nil {
		return nil, marshalErr
	}
	key := sha256.Sum256(identity)
	a.receipt = model.LegacyClientAdmission{RequestKey: hex.EncodeToString(key[:]), UserId: user.Id, InboundId: data.Id}
	loadErr := database.GetDB().Where("request_key = ?", a.receipt.RequestKey).First(&a.receipt).Error
	if loadErr == nil {
		a.persisted = true
		if err := a.validateReceipt(); err != nil {
			return nil, err
		}
		if a.receipt.Applied {
			keep = true
			return a, nil
		}
	} else if !errors.Is(loadErr, gorm.ErrRecordNotFound) {
		return nil, loadErr
	} else {
		posted := make([]model.Client, 0, len(clients))
		for _, client := range clients {
			posted = append(posted, client)
		}
		if taken, checkErr := svc.checkEmailsExistForClients(posted); checkErr != nil {
			return nil, checkErr
		} else if taken != "" {
			return nil, duplicateEmailError(taken, svc.emailHolders(taken)...)
		}
	}
	for _, id := range a.ids {
		if err := a.preflightCapacity(inbounds[id]); err != nil {
			return nil, err
		}
	}
	if !a.receipt.Applied {
		needCore, err := a.needsLiveCore(inbounds)
		if err != nil {
			return nil, err
		}
		if needCore && (!(&XrayService{}).IsXrayRunning() || p.GetAPIPort() <= 0) {
			return nil, errors.New("core is not running; active clients cannot be acknowledged without a restart")
		}
	}
	keep = true
	return a, nil
}

func (a *LegacyClientAddition) Close() {
	if a != nil && !a.closed {
		a.closed = true
		lock.Unlock()
		hotAddLock.Unlock()
	}
}

func (a *LegacyClientAddition) Persisted() bool { return a.persisted }
func (a *LegacyClientAddition) Projected() bool { return a.receipt.Projected }
func (a *LegacyClientAddition) Applied() bool   { return a.receipt.Applied }

func (a *LegacyClientAddition) Persist(data *model.Inbound) error {
	if a.closed || data == nil || data.Id != a.anchor {
		return errors.New("invalid or closed client addition")
	}
	if a.persisted {
		return a.validateReceipt()
	}
	_, emails, clients, err := legacyAdmissionRequest(data)
	if err != nil {
		return err
	}
	if strings.Join(emails, "\x00") != strings.Join(a.emails, "\x00") {
		return errors.New("priced client identities differ from the original request")
	}
	// Pricing may clamp expiry or remove reseller-only options, never replace
	// another account's login identity or credentials.
	for email, client := range clients {
		if !legacyAdmissionSameCredentials(a.requested[email], client) {
			return errors.New("priced client credentials differ from the original request")
		}
		// Do not hand the quota sweep an immediately expired enabled account:
		// legacy expiry enforcement can request a shared restart. An inactive,
		// non-renewing historical account remains a valid storage-only create.
		if client.ExpiryTime > 0 && client.ExpiryTime <= time.Now().UnixMilli() && (client.Enable || client.Reset > 0) {
			return errors.New("active or renewing clients require a future expiry; disable the client and automatic renewal to store an expired account")
		}
	}
	// Pricing can turn a posted past deadline into a fresh subscription. Recheck
	// the priced payload before committing, so a newly active request cannot
	// bypass the initial live-core gate.
	a.requested = clients
	inbounds := make(map[int]*model.Inbound, len(a.ids))
	var svc InboundService
	for _, id := range a.ids {
		ib, err := svc.GetInbound(id)
		if err != nil {
			return err
		}
		inbounds[id] = ib
		if err := a.preflightCapacity(ib); err != nil {
			return err
		}
	}
	if needed, err := a.needsLiveCore(inbounds); err != nil {
		return err
	} else if needed && (!(&XrayService{}).IsXrayRunning() || p.GetAPIPort() <= 0) {
		return errors.New("core is not running; active clients cannot be acknowledged without a restart")
	}
	if _, err := svc.addInboundClient(data, true, &a.receipt); err != nil {
		return err
	}
	a.persisted = true
	return a.validateReceipt()
}

func (a *LegacyClientAddition) MarkProjected() error {
	if a.closed || !a.persisted {
		return errors.New("client addition has not been persisted")
	}
	if err := a.validateReceipt(); err != nil {
		return err
	}
	if err := database.GetDB().Model(&model.LegacyClientAdmission{}).
		Where("request_key = ? AND user_id = ? AND inbound_id = ?", a.receipt.RequestKey, a.user.Id, a.anchor).
		Update("projected", true).Error; err != nil {
		return err
	}
	a.receipt.Projected = true
	return nil
}

// Apply activates only the requested accounts on their current intended
// memberships. It never calls a legacy reconcile hook or requests a restart.
func (a *LegacyClientAddition) Apply() error {
	if a.closed || !a.persisted || !a.receipt.Projected {
		return errors.New("client memberships have not been projected")
	}
	if err := a.validateReceipt(); err != nil {
		return err
	}
	if a.receipt.Applied {
		return nil
	}
	var svc InboundService
	actual, err := svc.inboundIdsServingEmails(database.GetDB(), a.emails)
	if err != nil {
		return err
	}
	if err := a.validateProjectedMemberships(actual); err != nil {
		return err
	}
	allowed := map[int]bool{}
	for _, id := range a.ids {
		allowed[id] = true
	}
	var api *xray.XrayAPI
	defer func() {
		if api != nil {
			api.Close()
		}
	}()
	appliedLive := false
	var admitted []struct {
		inbound int
		tag     string
		email   string
		native  bool
	}
	for _, id := range actual {
		if !allowed[id] {
			return errors.New("receipt account now belongs to an unexpected inbound")
		}
		ib, err := svc.GetInbound(id)
		if err != nil {
			return err
		}
		if !hotClientProtocol(ib.Protocol) {
			return errors.New("membership protocol changed during client addition")
		}
		if err := legacyAdmissionProtocol(ib); err != nil {
			return err
		}
		if err := a.preflightCapacity(ib); err != nil {
			return err
		}
		clients, err := svc.GetClients(ib)
		if err != nil {
			return err
		}
		present := map[string]bool{}
		for _, client := range clients {
			if _, requested := a.requested[accountKey(client.Email)]; requested {
				present[accountKey(client.Email)] = true
			}
		}
		for _, email := range a.emails {
			if !present[email] {
				return errors.New("requested client membership changed after projection")
			}
		}
		if err := hotInboundEligible(ib); errors.Is(err, errHotAdmissionIneligible) {
			continue
		} else if err != nil {
			return err
		}
		for _, client := range clients {
			wanted, selected := a.requested[accountKey(client.Email)]
			if !selected {
				continue
			}
			if !legacyAdmissionSameCredentials(wanted, client) && id == a.anchor {
				return errors.New("persisted client credentials changed after the request")
			}
			if !client.Enable {
				continue
			}
			if err := svc.hotClientEligible(client.Email); errors.Is(err, errHotAdmissionIneligible) {
				continue
			} else if err != nil {
				return err
			}
			if !(&XrayService{}).IsXrayRunning() || p.GetAPIPort() <= 0 {
				return errors.New("core is not running")
			}
			if ib.Protocol == model.WGC || ib.Protocol == model.AWG {
				var applyErr error
				if ib.Protocol == model.WGC {
					applyErr = (&WgcService{}).ApplyInboundHot(ib, client.Email)
				} else {
					applyErr = (&AwgService{}).ApplyInboundHot(ib, client.Email)
				}
				// Keep minted device keys in the accounts mirror even on a failed
				// live operation, so an exact retry never rotates them.
				if err := (&AccountService{}).SyncInboundAccounts(database.GetDB(), ib.Id); err != nil {
					return err
				}
				if applyErr != nil {
					return applyErr
				}
			} else {
				if api == nil {
					api = &xray.XrayAPI{}
					if err := api.Init(p.GetAPIPort()); err != nil {
						return err
					}
				}
				fields, err := hotAPIClientFields(ib, &client)
				if err != nil {
					return err
				}
				if err := api.EnsureUserHot(string(ib.Protocol), ib.Tag, fields); err != nil {
					return err
				}
				if err := svc.recheckHotNativeEligibility(api, ib.Id, ib.Tag, client.Email); err != nil {
					return err
				}
			}
			appliedLive = true
			admitted = append(admitted, struct {
				inbound int
				tag     string
				email   string
				native  bool
			}{ib.Id, ib.Tag, client.Email, ib.Protocol != model.WGC && ib.Protocol != model.AWG})
		}
	}
	if len(actual) != len(a.ids) {
		return errors.New("requested client memberships changed after projection")
	}
	if appliedLive {
		if err := (&XrayService{}).reloadRoutingHotLocked(); err != nil {
			return err
		}
	}
	for _, client := range admitted {
		if client.native {
			if err := svc.recheckHotNativeEligibility(api, client.inbound, client.tag, client.email); err != nil {
				return err
			}
		} else if err := svc.hotClientEligible(client.email); err != nil {
			return err
		}
	}
	if err := a.validateReceipt(); err != nil {
		return err
	}
	if err := database.GetDB().Model(&model.LegacyClientAdmission{}).
		Where("request_key = ? AND user_id = ? AND inbound_id = ?", a.receipt.RequestKey, a.user.Id, a.anchor).
		Update("applied", true).Error; err != nil {
		return err
	}
	a.receipt.Applied = true
	return nil
}

// Validate the entire fan-out before the first live operation. A later missing
// membership or an edited anchor must not partially admit an obsolete request.
func (a *LegacyClientAddition) validateProjectedMemberships(actual []int) error {
	if len(actual) != len(a.ids) {
		return errors.New("requested client memberships changed after projection")
	}
	allowed := map[int]bool{}
	for _, id := range a.ids {
		allowed[id] = true
	}
	var svc InboundService
	for _, id := range actual {
		if !allowed[id] {
			return errors.New("receipt account now belongs to an unexpected inbound")
		}
		ib, err := svc.GetInbound(id)
		if err != nil {
			return err
		}
		clients, err := svc.GetClients(ib)
		if err != nil {
			return err
		}
		present := map[string]bool{}
		for _, client := range clients {
			wanted, selected := a.requested[accountKey(client.Email)]
			if !selected {
				continue
			}
			present[accountKey(client.Email)] = true
			if id == a.anchor && !legacyAdmissionSameCredentials(wanted, client) {
				return errors.New("persisted client credentials changed after the request")
			}
		}
		for _, email := range a.emails {
			if !present[email] {
				return errors.New("requested client membership changed after projection")
			}
		}
	}
	return nil
}

func (a *LegacyClientAddition) validateReceipt() error {
	if a.receipt.UserId != a.user.Id || a.receipt.InboundId != a.anchor {
		return errors.New("admission receipt belongs to a different caller or inbound")
	}
	var identities map[string]int
	if err := json.Unmarshal([]byte(a.receipt.ClientIDs), &identities); err != nil {
		return err
	}
	if len(identities) != len(a.emails) {
		return errors.New("admission receipt identities differ from the request")
	}
	for _, email := range a.emails {
		id := identities[email]
		if id <= 0 {
			return errors.New("admission receipt has no persisted client identity")
		}
		var traffic xray.ClientTraffic
		if err := database.GetDB().Where("id = ? AND LOWER(TRIM(email)) = ?", id, email).First(&traffic).Error; err != nil {
			return fmt.Errorf("receipt account was deleted or recreated: %w", err)
		}
		if a.user.IsReseller {
			owned, err := (&ResellerService{}).OwnsClientEmail(traffic.Email, a.user.Id)
			if err != nil {
				return err
			}
			if !owned {
				return ErrClientNotOwned
			}
		}
	}
	return nil
}

func legacyAdmissionIDs(ids []int) []int {
	set := map[int]bool{}
	for _, id := range ids {
		if id > 0 {
			set[id] = true
		}
	}
	out := make([]int, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Ints(out)
	return out
}

func legacyAdmissionRequest(data *model.Inbound) ([]byte, []string, map[string]model.Client, error) {
	var settings map[string]any
	decoder := json.NewDecoder(strings.NewReader(data.Settings))
	decoder.UseNumber()
	if err := decoder.Decode(&settings); err != nil {
		return nil, nil, nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, nil, nil, errors.New("client settings must contain exactly one JSON object")
	}
	clients, ok := settings["clients"].([]any)
	if !ok || len(clients) == 0 {
		return nil, nil, nil, errors.New("client addition requires a nonempty client array")
	}
	byEmail := map[string]model.Client{}
	emails := make([]string, 0, len(clients))
	for _, raw := range clients {
		entry, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, nil, errors.New("client entry must be an object")
		}
		email, _ := entry["email"].(string)
		email = strings.TrimSpace(email)
		if err := ValidateClientEmail(email); err != nil {
			return nil, nil, nil, err
		}
		email = accountKey(email)
		if _, duplicate := byEmail[email]; duplicate {
			return nil, nil, nil, errors.New("client addition contains a duplicate email")
		}
		entry["email"] = email
		encoded, err := json.Marshal(entry)
		if err != nil {
			return nil, nil, nil, err
		}
		var client model.Client
		if err := json.Unmarshal(encoded, &client); err != nil {
			return nil, nil, nil, err
		}
		byEmail[email] = client
		emails = append(emails, email)
	}
	canonical, err := json.Marshal(settings)
	return canonical, emails, byEmail, err
}

func legacyAdmissionSameCredentials(a, b model.Client) bool {
	return a.ID == b.ID && a.Password == b.Password && a.Auth == b.Auth && a.Username == b.Username
}

func legacyAdmissionProtocol(ib *model.Inbound) error {
	if ib.Protocol != model.Shadowsocks {
		return nil
	}
	var settings struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal([]byte(ib.Settings), &settings); err != nil {
		return err
	}
	if strings.HasPrefix(settings.Method, "2022-") && settings.Method != "2022-blake3-aes-128-gcm" && settings.Method != "2022-blake3-aes-256-gcm" {
		return errors.New("Shadowsocks 2022 live users require blake3-aes-128-gcm or blake3-aes-256-gcm")
	}
	return nil
}

func (a *LegacyClientAddition) needsLiveCore(inbounds map[int]*model.Inbound) (bool, error) {
	now := time.Now().UnixMilli()
	for _, id := range a.ids {
		if ib := inbounds[id]; ib != nil && hotInboundEligible(ib) == nil {
			for _, client := range a.requested {
				if client.Enable && (client.ExpiryTime <= 0 || client.ExpiryTime > now) {
					if a.persisted {
						err := (&InboundService{}).hotClientEligible(client.Email)
						if errors.Is(err, errHotAdmissionIneligible) {
							continue
						} else if err != nil {
							return false, err
						}
					}
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func (a *LegacyClientAddition) preflightCapacity(ib *model.Inbound) error {
	if ib == nil || ib.Protocol != model.WGC && ib.Protocol != model.AWG {
		return nil
	}
	report, ok := InboundAddressing(ib)
	if !ok || report.Capacity <= 0 {
		return errors.New("kernel WireGuard inbound has no existing address capacity; initialize its pool separately")
	}
	var svc InboundService
	clients, err := svc.GetClients(ib)
	if err != nil {
		return err
	}
	owners := map[int]string{}
	present := map[string]bool{}
	for i, client := range clients {
		slot, email := slotOr(client.Slot, i), accountKey(client.Email)
		if previous, duplicate := owners[slot]; duplicate && previous != email {
			return errors.New("existing WireGuard accounts share a pool slot; migrate them separately")
		}
		if slot < 0 || slot >= report.Capacity {
			return errors.New("existing WireGuard account exceeds its current pool; migrate it separately")
		}
		owners[slot], present[email] = email, true
	}
	for _, email := range a.emails {
		if present[email] {
			continue
		}
		slot := 0
		if requested := a.requested[email].Slot; requested != nil {
			slot = *requested
		} else {
			for owners[slot] != "" {
				slot++
			}
		}
		if slot < 0 || slot >= report.Capacity || owners[slot] != "" {
			return errors.New("new WireGuard account does not fit the current pool without moving existing addresses")
		}
		owners[slot] = email
	}
	return nil
}
