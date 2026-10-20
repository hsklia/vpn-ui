package service

import (
	"bytes"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestLegacyAdmissionRequestPreservesLargeIntegerIdentity(t *testing.T) {
	first, _, _, err := legacyAdmissionRequest(&model.Inbound{Settings: `{"clients":[{"email":"player","id":"player","totalGB":9007199254740992}]}`})
	if err != nil {
		t.Fatal(err)
	}
	second, _, _, err := legacyAdmissionRequest(&model.Inbound{Settings: `{"clients":[{"email":"player","id":"player","totalGB":9007199254740993}]}`})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) || !bytes.Contains(second, []byte("9007199254740993")) {
		t.Fatal("distinct large integer requests acquired the same canonical identity")
	}
}

func TestLegacyAdmissionRequestCanonicalizesEmailAndObjectOrder(t *testing.T) {
	first, emails, _, err := legacyAdmissionRequest(&model.Inbound{Settings: ` { "other": { "b":2,"a":1 }, "clients":[{"totalGB":9007199254740993,"id":"player","email":" Player@Example.test "}] } `})
	if err != nil {
		t.Fatal(err)
	}
	second, _, _, err := legacyAdmissionRequest(&model.Inbound{Settings: `{"clients":[{"email":"player@example.test","id":"player","totalGB":9007199254740993}],"other":{"a":1,"b":2}}`})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || len(emails) != 1 || emails[0] != "player@example.test" {
		t.Fatal("email normalization or object order changed the canonical request")
	}
}

func TestLegacyAdmissionRequestRejectsTrailingJSON(t *testing.T) {
	for _, suffix := range []string{` {}`, ` null`, ` trailing`} {
		_, _, _, err := legacyAdmissionRequest(&model.Inbound{Settings: `{"clients":[{"email":"player","id":"player"}]}` + suffix})
		if err == nil {
			t.Fatalf("accepted trailing data %q", suffix)
		}
	}
}
