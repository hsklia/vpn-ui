package controller

import (
	"encoding/json"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestHotEndpointsEnforceOwnershipBeforePersistence(t *testing.T) {
	f := newIdorFixture(t)
	for _, endpoint := range []string{"addClientHot", "addPeerHot"} {
		body := url.Values{"id": {strconv.Itoa(f.aliInbound.Id)}, "settings": {`{"clients":[{"email":"unauthorized","id":"abc","enable":true}]}`}}.Encode()
		response := f.as(t, f.reza, http.MethodPost, "/panel/api/inbounds/"+endpoint, body)
		var msg struct {
			Success bool `json:"success"`
			Obj     any  `json:"obj"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &msg); err != nil {
			t.Fatal(err)
		}
		if msg.Success || msg.Obj != nil {
			t.Fatalf("unauthorized %s acknowledged: %s", endpoint, response.Body.String())
		}
	}
}
func TestHotEndpointsDoNotAcknowledgeFailedApply(t *testing.T) {
	f := newIdorFixture(t)
	body := url.Values{"id": {strconv.Itoa(f.rezaInbound.Id)}, "settings": {`{"clients":[{"email":"hot-created","id":"9f1c1e2a-0000-4000-8000-abcdefabcdef","enable":true}]}`}}.Encode()
	response := f.as(t, f.reza, http.MethodPost, "/panel/api/inbounds/addClientHot", body)
	if strings.Contains(response.Body.String(), `"applied":true`) || strings.Contains(response.Body.String(), `"success":true`) {
		t.Fatalf("failed apply acknowledged: %s", response.Body.String())
	}
}
func TestHotEndpointsRejectReseller(t *testing.T) {
	f := newIdorFixture(t)
	user := *f.reza
	user.IsReseller = true
	body := url.Values{"id": {strconv.Itoa(f.rezaInbound.Id)}, "settings": {`{"clients":[]}`}}.Encode()
	response := f.as(t, &user, http.MethodPost, "/panel/api/inbounds/addClientHot", body)
	if !strings.Contains(response.Body.String(), "administrator") {
		t.Fatalf("reseller bypassed priced create workflow: %s", response.Body.String())
	}
	user.IsReseller = false
	user.Permissions = model.Permission(0)
	response = f.as(t, &user, http.MethodPost, "/panel/api/inbounds/addClientHot", body)
	if response.Code == http.StatusOK && strings.Contains(response.Body.String(), `"success":true`) {
		t.Fatal("missing create-client permission accepted")
	}
}
