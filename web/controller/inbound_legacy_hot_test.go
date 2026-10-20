package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
	"gorm.io/gorm"
)

// Exercise the ordinary panel route, including its ownership and reseller gates.
// These tests deliberately have no live core: an enabled admission must report
// failure without scheduling a shared restart; disabled admissions need storage
// only and can exercise the complete receipt/billing retry contract offline.
func legacyHotSetInbound(t *testing.T, inbound *model.Inbound, protocol model.Protocol, enabled bool) {
	t.Helper()
	// The reseller fixture updates its shared settings in SQL after constructing
	// the inbound pointer. Read that current row before changing its protocol.
	if err := database.GetDB().First(inbound, inbound.Id).Error; err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		t.Fatal(err)
	}
	settings["userLimit"] = 10
	settings["futureOption"] = map[string]any{"retain": true}
	body, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	inbound.Protocol, inbound.Enable, inbound.Settings = protocol, enabled, string(body)
	if err := database.GetDB().Save(inbound).Error; err != nil {
		t.Fatal(err)
	}
	drainRestartFlag()
	t.Cleanup(func() { drainRestartFlag() })
}

func legacyHotClient(email string, enabled bool) map[string]any {
	return map[string]any{
		"id": "b4a697f5-cf2a-4547-9b98-90333e5f8fca", "email": email,
		"enable": enabled, "totalGB": 5 * testGB, "expiryTime": 0,
	}
}

func legacyHotForm(t *testing.T, inboundID int, clients []map[string]any, memberships ...int) string {
	t.Helper()
	settings, err := json.Marshal(map[string]any{"clients": clients})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"id": {strconv.Itoa(inboundID)}, "settings": {string(settings)}}
	for _, id := range memberships {
		form.Add("inboundIds", strconv.Itoa(id))
	}
	return form.Encode()
}

func legacyHotPost(t *testing.T, f *idorFixture, user *model.User, body string) bool {
	t.Helper()
	response := f.as(t, user, http.MethodPost, "/panel/api/inbounds/addClient", body)
	var message map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &message); err != nil {
		t.Fatalf("ordinary create returned non-JSON HTTP %d: %s", response.Code, response.Body.String())
	}
	success, ok := message["success"].(bool)
	if !ok {
		t.Fatalf("ordinary create omitted success: %s", response.Body.String())
	}
	if drainRestartFlag() {
		t.Error("ordinary WG-C/AWG create or retry requested a shared core restart")
	}
	return success
}

func legacyHotEntries(t *testing.T, inboundID int) map[string]map[string]any {
	t.Helper()
	var inbound model.Inbound
	if err := database.GetDB().First(&inbound, inboundID).Error; err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(settings["futureOption"], map[string]any{"retain": true}) {
		t.Fatal("ordinary create removed an unrelated inbound option")
	}
	entries := make(map[string]map[string]any)
	clients, ok := settings["clients"].([]any)
	if !ok {
		t.Fatal("stored inbound has no client array")
	}
	for _, value := range clients {
		client, ok := value.(map[string]any)
		if !ok {
			t.Fatal("stored client is not an object")
		}
		email, _ := client["email"].(string)
		if _, duplicate := entries[email]; duplicate {
			t.Fatalf("retry duplicated account %q", email)
		}
		entries[email] = client
	}
	return entries
}

func legacyHotTraffic(t *testing.T, email string) xray.ClientTraffic {
	t.Helper()
	var rows []xray.ClientTraffic
	if err := database.GetDB().Where("email = ?", email).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("account %q has %d traffic rows, want one", email, len(rows))
	}
	return rows[0]
}

func TestLegacyHotCreateFailedApplyNeverAcknowledgesOrRestarts(t *testing.T) {
	for _, protocol := range []model.Protocol{model.WGC, model.AWG} {
		for _, count := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/%d-clients", protocol, count), func(t *testing.T) {
				f := newIdorFixture(t)
				legacyHotSetInbound(t, f.rezaInbound, protocol, true)
				before := legacyHotEntries(t, f.rezaInbound.Id)
				clients := make([]map[string]any, count)
				for index := range clients {
					clients[index] = legacyHotClient(fmt.Sprintf("pending-%d", index), true)
					clients[index]["id"] = fmt.Sprintf("b4a697f5-cf2a-4547-9b98-%012d", index+1)
				}
				body := legacyHotForm(t, f.rezaInbound.Id, clients)
				if legacyHotPost(t, f, f.reza, body) {
					t.Error("missing live core was acknowledged as a successful creation")
				}
				after := legacyHotEntries(t, f.rezaInbound.Id)
				// A preflight rejection stores nothing. An apply failure after the
				// atomic write may leave the complete batch for a receipt retry.
				if len(after) != len(before) && len(after) != len(before)+count {
					t.Fatal("failed create left a partially persisted batch")
				}
				for email, previous := range before {
					if !reflect.DeepEqual(previous, after[email]) {
						t.Fatalf("failed admission changed existing account %q", email)
					}
				}
				if legacyHotPost(t, f, f.reza, body) {
					t.Error("retry still has no live core but was acknowledged")
				}
				if !reflect.DeepEqual(after, legacyHotEntries(t, f.rezaInbound.Id)) {
					t.Fatal("failed retry duplicated or rewrote persisted credentials")
				}
			})
		}
	}
}

func TestLegacyHotCreateDisabledAdmissionAndExactRetry(t *testing.T) {
	for _, protocol := range []model.Protocol{model.WGC, model.AWG} {
		for _, inboundEnabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/inbound-enabled-%t", protocol, inboundEnabled), func(t *testing.T) {
				f := newIdorFixture(t)
				legacyHotSetInbound(t, f.rezaInbound, protocol, inboundEnabled)
				clientEnabled := !inboundEnabled
				body := legacyHotForm(t, f.rezaInbound.Id, []map[string]any{legacyHotClient("disabled-admission", clientEnabled)})
				if !legacyHotPost(t, f, f.reza, body) {
					t.Fatal("a disabled inbound/client must remain creatable without a live core")
				}
				stored := legacyHotEntries(t, f.rezaInbound.Id)
				if stored["disabled-admission"]["enable"] != clientEnabled {
					t.Fatal("create changed the posted account enable flag")
				}
				identity := legacyHotTraffic(t, "disabled-admission").Id
				if !legacyHotPost(t, f, f.reza, body) {
					t.Fatal("an applied exact-request receipt did not acknowledge its retry")
				}
				if !reflect.DeepEqual(stored, legacyHotEntries(t, f.rezaInbound.Id)) || legacyHotTraffic(t, "disabled-admission").Id != identity {
					t.Fatal("applied retry rewrote account material or replaced its identity")
				}
				// An applied receipt must not bypass a permission revoked afterward.
				limited := *f.reza
				limited.Permissions &^= model.PermCreateClient
				if legacyHotPost(t, f, &limited, body) {
					t.Fatal("an applied receipt bypassed the create-client permission")
				}
			})
		}
	}
}

func TestLegacyHotCreateBulkMembershipCanonicalRetry(t *testing.T) {
	f := newIdorFixture(t)
	legacyHotSetInbound(t, f.aliInbound, model.WGC, false)
	legacyHotSetInbound(t, f.rezaInbound, model.AWG, false)
	if err := database.GetDB().Create(&model.InboundAccess{UserId: f.reza.Id, InboundId: f.aliInbound.Id}).Error; err != nil {
		t.Fatal(err)
	}
	clients := []map[string]any{legacyHotClient("bulk-first", true), legacyHotClient("bulk-second", true)}
	clients[1]["id"] = "9fc597bf-ad30-446a-9864-36715af15628"
	body := legacyHotForm(t, f.aliInbound.Id, clients, f.aliInbound.Id, f.rezaInbound.Id)
	if !legacyHotPost(t, f, f.reza, body) {
		t.Fatal("disabled bulk membership create failed")
	}
	before := map[int]map[string]map[string]any{}
	identities := map[string]int{}
	for _, inbound := range []*model.Inbound{f.aliInbound, f.rezaInbound} {
		before[inbound.Id] = legacyHotEntries(t, inbound.Id)
		for _, email := range []string{"bulk-first", "bulk-second"} {
			if before[inbound.Id][email] == nil {
				t.Fatalf("bulk account %q never reached membership %d", email, inbound.Id)
			}
			identities[email] = legacyHotTraffic(t, email).Id
		}
	}
	// Whitespace/key serialization and the checkbox order do not create a new
	// admission. The target set and canonical JSON identify the same request.
	form, err := url.ParseQuery(legacyHotForm(t, f.aliInbound.Id, clients, f.rezaInbound.Id, f.aliInbound.Id))
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, []byte(form.Get("settings")), "", "  "); err != nil {
		t.Fatal(err)
	}
	form.Set("settings", pretty.String())
	if !legacyHotPost(t, f, f.reza, form.Encode()) {
		t.Fatal("canonical exact request was not recognized after serialization/order changes")
	}
	for id, previous := range before {
		if !reflect.DeepEqual(previous, legacyHotEntries(t, id)) {
			t.Fatalf("retry changed membership %d credentials or slots", id)
		}
	}
	for email, identity := range identities {
		if legacyHotTraffic(t, email).Id != identity {
			t.Fatal("bulk receipt retry replaced an account identity")
		}
	}
}

func TestLegacyHotCreateRejectsForeignAndUnsupportedMembershipBeforeWrite(t *testing.T) {
	for _, foreign := range []bool{true, false} {
		t.Run(fmt.Sprintf("foreign-%t", foreign), func(t *testing.T) {
			f := newIdorFixture(t)
			legacyHotSetInbound(t, f.rezaInbound, model.WGC, false)
			legacyHotSetInbound(t, f.aliInbound, model.L2TP, false)
			if !foreign {
				if err := database.GetDB().Create(&model.InboundAccess{UserId: f.reza.Id, InboundId: f.aliInbound.Id}).Error; err != nil {
					t.Fatal(err)
				}
			}
			before := legacyHotEntries(t, f.rezaInbound.Id)
			other := legacyHotEntries(t, f.aliInbound.Id)
			body := legacyHotForm(t, f.rezaInbound.Id, []map[string]any{legacyHotClient("refused-membership", true)}, f.rezaInbound.Id, f.aliInbound.Id)
			if legacyHotPost(t, f, f.reza, body) {
				t.Fatal("foreign/unsupported mixed membership was accepted")
			}
			if !reflect.DeepEqual(before, legacyHotEntries(t, f.rezaInbound.Id)) || !reflect.DeepEqual(other, legacyHotEntries(t, f.aliInbound.Id)) {
				t.Fatal("refused membership request persisted an account")
			}
		})
	}
}

func TestLegacyHotCreateResellerChargesOnceAndKeepsCreateGuards(t *testing.T) {
	f := newResellerFixture(t)
	legacyHotSetInbound(t, f.aliInbound, model.WGC, false)
	if err := database.GetDB().Model(&model.ResellerProfile{}).Where("user_id = ?", f.sara.Id).Update("days_per_gb", 2).Error; err != nil {
		t.Fatal(err)
	}
	previousSpent := f.spent(t)
	client := legacyHotClient("priced-created", true)
	body := legacyHotForm(t, f.aliInbound.Id, []map[string]any{client})
	started := time.Now()
	if !legacyHotPost(t, f.idorFixture, f.sara, body) {
		t.Fatal("reseller lost the normal priced create workflow")
	}
	stored := legacyHotEntries(t, f.aliInbound.Id)
	traffic := legacyHotTraffic(t, "priced-created")
	wantExpiry := started.Add(10 * 24 * time.Hour).UnixMilli()
	if traffic.Total != 5*testGB || traffic.ExpiryTime < wantExpiry-5000 || traffic.ExpiryTime > wantExpiry+5000 {
		t.Fatal("priced create bypassed the reseller quota/duration policy")
	}
	var ledger model.ResellerClient
	if err := database.GetDB().Where("email = ?", "priced-created").First(&ledger).Error; err != nil {
		t.Fatal(err)
	}
	if f.spent(t) != previousSpent+5*testGB || ledger.UserId != f.sara.Id || ledger.ChargedBytes != 5*testGB {
		t.Fatal("reseller create did not reserve exactly one account's quota")
	}
	if !legacyHotPost(t, f.idorFixture, f.sara, body) {
		t.Fatal("the reseller's applied exact-request receipt was not reusable")
	}
	if f.spent(t) != previousSpent+5*testGB || !reflect.DeepEqual(traffic, legacyHotTraffic(t, "priced-created")) || !reflect.DeepEqual(stored, legacyHotEntries(t, f.aliInbound.Id)) {
		t.Fatal("retry double-charged, extended expiry or changed account credentials")
	}
	changed := legacyHotClient("priced-created", true)
	changed["id"] = "c96e9059-ed78-4ebd-b378-bdfb2a1e48b7"
	changed["totalGB"] = 6 * testGB
	if legacyHotPost(t, f.idorFixture, f.sara, legacyHotForm(t, f.aliInbound.Id, []map[string]any{changed})) {
		t.Fatal("a different request adopted another receipt by email alone")
	}
	if legacyHotPost(t, f.idorFixture, f.ali, body) {
		t.Fatal("another caller adopted the reseller's receipt")
	}
	if f.spent(t) != previousSpent+5*testGB || !reflect.DeepEqual(stored, legacyHotEntries(t, f.aliInbound.Id)) {
		t.Fatal("rejected receipt adoption changed billing or account material")
	}
}

func TestLegacyHotCreateResellerRejectionLeavesNoChargeOrClient(t *testing.T) {
	for _, reason := range []string{"insufficient-balance", "admin-email", "invalid-identity", "bulk"} {
		t.Run(reason, func(t *testing.T) {
			f := newResellerFixture(t)
			legacyHotSetInbound(t, f.aliInbound, model.WGC, false)
			before := legacyHotEntries(t, f.aliInbound.Id)
			spent := f.spent(t)
			client := legacyHotClient("refused-priced", true)
			clients := []map[string]any{client}
			switch reason {
			case "insufficient-balance":
				client["totalGB"] = 91 * testGB // only 90 GB remains
			case "admin-email":
				client["email"] = f.aliEmail
			case "invalid-identity":
				client["email"] = "invalid>identity"
			case "bulk":
				second := legacyHotClient("second-priced", true)
				second["id"] = "9fc597bf-ad30-446a-9864-36715af15628"
				clients = append(clients, second)
			}
			if legacyHotPost(t, f.idorFixture, f.sara, legacyHotForm(t, f.aliInbound.Id, clients)) {
				t.Fatal("invalid reseller create was accepted")
			}
			if f.spent(t) != spent || !reflect.DeepEqual(before, legacyHotEntries(t, f.aliInbound.Id)) {
				t.Fatal("rejected create retained a charge or changed stored clients")
			}
			var unexpected int64
			if err := database.GetDB().Model(&model.ResellerClient{}).Where("email IN ?", []string{"refused-priced", "second-priced", "invalid>identity", f.aliEmail}).Count(&unexpected).Error; err != nil {
				t.Fatal(err)
			}
			if unexpected != 0 {
				t.Fatal("rejected create retained a ledger row or claimed an administrator's account")
			}
		})
	}
}

func TestLegacyHotCreateReceiptCannotAdoptRecreatedTrafficIdentity(t *testing.T) {
	f := newIdorFixture(t)
	legacyHotSetInbound(t, f.rezaInbound, model.WGC, false)
	body := legacyHotForm(t, f.rezaInbound.Id, []map[string]any{legacyHotClient("recreated-account", true)})
	if !legacyHotPost(t, f, f.reza, body) {
		t.Fatal("initial disabled create failed")
	}
	original := legacyHotTraffic(t, "recreated-account")
	if err := database.GetDB().Delete(&original).Error; err != nil {
		t.Fatal(err)
	}
	recreated := original
	recreated.Id = 0
	if err := database.GetDB().Create(&recreated).Error; err != nil {
		t.Fatal(err)
	}
	if recreated.Id == original.Id {
		t.Fatal("fixture did not replace the traffic primary key")
	}
	before := legacyHotEntries(t, f.rezaInbound.Id)
	if legacyHotPost(t, f, f.reza, body) {
		t.Fatal("stale receipt adopted a deleted/recreated account with the same email")
	}
	if !reflect.DeepEqual(before, legacyHotEntries(t, f.rezaInbound.Id)) || legacyHotTraffic(t, "recreated-account").Id != recreated.Id {
		t.Fatal("rejected receipt changed the replacement account")
	}
}

func TestLegacyHotCreateAppliedReceiptDoesNotRequireCoreAgain(t *testing.T) {
	f := newIdorFixture(t)
	legacyHotSetInbound(t, f.rezaInbound, model.WGC, false)
	body := legacyHotForm(t, f.rezaInbound.Id, []map[string]any{legacyHotClient("already-applied", true)})
	if !legacyHotPost(t, f, f.reza, body) {
		t.Fatal("initial disabled admission failed")
	}
	stored := legacyHotEntries(t, f.rezaInbound.Id)
	identity := legacyHotTraffic(t, "already-applied").Id
	// A later structural edit does not turn an already acknowledged creation
	// into a new live activation request. The receipt retries as a no-op, while
	// its caller/ownership/traffic-primary-key checks must still run.
	if err := database.GetDB().Model(&model.Inbound{}).Where("id = ?", f.rezaInbound.Id).Update("enable", true).Error; err != nil {
		t.Fatal(err)
	}
	if !legacyHotPost(t, f, f.reza, body) {
		t.Fatal("an applied receipt required a running core again")
	}
	if !reflect.DeepEqual(stored, legacyHotEntries(t, f.rezaInbound.Id)) || legacyHotTraffic(t, "already-applied").Id != identity {
		t.Fatal("an applied retry changed stored account material")
	}
}

func TestLegacyHotCreatePostCommitReadFailureKeepsResellerReservation(t *testing.T) {
	f := newResellerFixture(t)
	legacyHotSetInbound(t, f.aliInbound, model.WGC, false)
	spent := f.spent(t)
	const email = "committed-priced"
	body := legacyHotForm(t, f.aliInbound.Id, []map[string]any{legacyHotClient(email, true)})
	// Inject a transient read failure only after the account exists outside the
	// write transaction. This exercises an error returned after Persist committed,
	// rather than a failed INSERT which should refund its reservation.
	injected := false
	const callback = "test:legacy-admission-post-commit-read"
	queries := database.GetDB().Callback().Query()
	if err := queries.After("gorm:query").Register(callback, func(tx *gorm.DB) {
		if injected || tx.Statement.Table != "client_traffics" {
			return
		}
		if _, insideTransaction := tx.Statement.ConnPool.(interface{ Commit() error }); insideTransaction {
			return
		}
		row, ok := tx.Statement.Dest.(*xray.ClientTraffic)
		if !ok || row.Email != email || row.Id <= 0 {
			return
		}
		injected = true
		tx.AddError(errors.New("temporary receipt identity read failure"))
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queries.Remove(callback) })
	if legacyHotPost(t, f.idorFixture, f.sara, body) {
		t.Fatal("a post-commit validation failure was acknowledged")
	}
	if !injected {
		t.Fatal("fixture did not reach the post-commit identity read")
	}
	if legacyHotEntries(t, f.aliInbound.Id)[email] == nil {
		t.Fatal("fixture did not commit the new account")
	}
	var ledger model.ResellerClient
	if err := database.GetDB().Where("email = ?", email).First(&ledger).Error; err != nil {
		t.Fatal("a committed account lost its reseller ledger: ", err)
	}
	if f.spent(t) != spent+5*testGB || ledger.UserId != f.sara.Id || ledger.ChargedBytes != 5*testGB {
		t.Fatal("an error after commit refunded the still-persisted account")
	}
	if !legacyHotPost(t, f.idorFixture, f.sara, body) {
		t.Fatal("the committed receipt did not recover after a transient read failure")
	}
	if f.spent(t) != spent+5*testGB || legacyHotTraffic(t, email).Total != 5*testGB {
		t.Fatal("post-commit retry double-charged or changed the account quota")
	}
}

func TestLegacyHotCreateExpiredAdmissionsPreserveBillingAndDisabledStorage(t *testing.T) {
	for _, test := range []struct {
		name    string
		enabled bool
		reset   int
		allowed bool
	}{
		{"active-expired", true, 0, false},
		{"disabled-expired", false, 0, true},
		{"reseller-reset-stripped-before-expiry-check", false, 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newResellerFixture(t)
			// An inactive inbound avoids the missing-core preflight so the request
			// reaches the expiry check after the normal reseller reservation.
			legacyHotSetInbound(t, f.aliInbound, model.WGC, false)
			before := legacyHotEntries(t, f.aliInbound.Id)
			spent := f.spent(t)
			const email = "expiry-guard"
			expiredAt := time.Now().Add(-time.Minute).UnixMilli()
			client := legacyHotClient(email, test.enabled)
			client["expiryTime"], client["reset"] = expiredAt, test.reset
			body := legacyHotForm(t, f.aliInbound.Id, []map[string]any{client})
			if got := legacyHotPost(t, f.idorFixture, f.sara, body); got != test.allowed {
				t.Fatalf("expired create success=%t, want %t", got, test.allowed)
			}
			if test.allowed {
				traffic := legacyHotTraffic(t, email)
				// Pricing always strips reseller resets, including a posted reset=1.
				// Eligibility must inspect that final priced value before persistence.
				if traffic.Enable || traffic.ExpiryTime != expiredAt || traffic.Reset != 0 {
					t.Fatal("disabled expired creation changed its enable/expiry/reset state")
				}
				if f.spent(t) != spent+5*testGB || legacyHotEntries(t, f.aliInbound.Id)[email] == nil {
					t.Fatal("disabled expired account lost its ordinary reservation or storage")
				}
				return
			}
			if f.spent(t) != spent || !reflect.DeepEqual(before, legacyHotEntries(t, f.aliInbound.Id)) {
				t.Fatal("refused expired admission persisted an account or retained a charge")
			}
			var traffics, ledgers int64
			if err := database.GetDB().Model(&xray.ClientTraffic{}).Where("email = ?", email).Count(&traffics).Error; err != nil {
				t.Fatal(err)
			}
			if err := database.GetDB().Model(&model.ResellerClient{}).Where("email = ?", email).Count(&ledgers).Error; err != nil {
				t.Fatal(err)
			}
			if traffics != 0 || ledgers != 0 {
				t.Fatal("refused expired admission left a traffic identity or reseller ledger")
			}
		})
	}
}

func TestLegacyHotCreateAdminExpiredResetIsRejectedBeforeStorage(t *testing.T) {
	f := newIdorFixture(t)
	legacyHotSetInbound(t, f.rezaInbound, model.WGC, false)
	before := legacyHotEntries(t, f.rezaInbound.Id)
	const email = "admin-expired-reset"
	client := legacyHotClient(email, false)
	client["expiryTime"] = time.Now().Add(-time.Minute).UnixMilli()
	client["reset"] = 1
	// Admin creation does not go through the reseller reset clamp. Keeping this
	// positive reset would make the expiry sweep renew it and request a restart.
	if legacyHotPost(t, f, f.reza, legacyHotForm(t, f.rezaInbound.Id, []map[string]any{client})) {
		t.Fatal("administrator's expired reset account was accepted")
	}
	if !reflect.DeepEqual(before, legacyHotEntries(t, f.rezaInbound.Id)) {
		t.Fatal("rejected expired reset account changed inbound storage")
	}
	var count int64
	if err := database.GetDB().Model(&xray.ClientTraffic{}).Where("email = ?", email).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("rejected expired reset account retained a traffic identity")
	}
}
