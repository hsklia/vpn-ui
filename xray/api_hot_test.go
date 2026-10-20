package xray

import (
	"context"
	"errors"
	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"strings"
	"testing"
)

type hotHandler struct {
	command.HandlerServiceClient
	users              []*protocol.User
	queryErr, applyErr error
	adds               int
}

func (h *hotHandler) GetInboundUsers(context.Context, *command.GetInboundUserRequest, ...grpc.CallOption) (*command.GetInboundUserResponse, error) {
	return &command.GetInboundUserResponse{Users: h.users}, h.queryErr
}
func (h *hotHandler) AlterInbound(_ context.Context, req *command.AlterInboundRequest, _ ...grpc.CallOption) (*command.AlterInboundResponse, error) {
	op, err := req.Operation.GetInstance()
	if err != nil {
		return nil, err
	}
	if _, ok := op.(*command.AddUserOperation); !ok {
		return nil, errors.New("hot path attempted a non-add operation")
	}
	h.adds++
	return &command.AlterInboundResponse{}, h.applyErr
}
func hotAPI(h *hotHandler) *XrayAPI {
	var client command.HandlerServiceClient = h
	return &XrayAPI{HandlerServiceClient: &client}
}

func TestHotUserRetriesCompareCredentialsAndDoNotReplace(t *testing.T) {
	fields := map[string]any{"email": "existing", "id": "9f1c1e2a-0000-4000-8000-abcdefabcdef"}
	want, err := buildAPIUser("vmess", fields)
	if err != nil {
		t.Fatal(err)
	}
	memory, err := want.ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	h := &hotHandler{users: []*protocol.User{protocol.ToProtoUser(memory)}}
	if err := hotAPI(h).EnsureUserHot("vmess", "tag", fields); err != nil {
		t.Fatal(err)
	}
	if h.adds != 0 {
		t.Fatal("retry rewrote a live account")
	}
	fields["id"] = "9f1c1e2a-0000-4000-8000-ffffffffffff"
	if err := hotAPI(h).EnsureUserHot("vmess", "tag", fields); err == nil {
		t.Fatal("conflicting live credentials accepted")
	}
	if h.adds != 0 {
		t.Fatal("conflict replaced a live account")
	}
}
func TestHotUserApplyAndQueryErrorsAreReturned(t *testing.T) {
	fields := map[string]any{"email": "new", "password": "secret"}
	for _, queryFailure := range []bool{false, true} {
		h := &hotHandler{applyErr: errors.New("rejected")}
		if queryFailure {
			h.queryErr = errors.New("unavailable")
		}
		if err := hotAPI(h).EnsureUserHot("trojan", "tag", fields); err == nil {
			t.Fatal("failed runtime operation acknowledged")
		}
		expected := 1
		if queryFailure {
			expected = 0
		}
		if h.adds != expected {
			t.Fatalf("adds=%d want %d", h.adds, expected)
		}
	}
	if err := hotAPI(&hotHandler{}).EnsureUserHot("unsupported", "tag", fields); err == nil {
		t.Fatal("unsupported protocol silently accepted")
	}
}
func TestHotWireguardAccountHasHexKeysAndNoEndpoint(t *testing.T) {
	priv, _ := wgtypes.GeneratePrivateKey()
	psk, _ := wgtypes.GenerateKey()
	u, err := buildAPIUser("wireguard", map[string]any{"email": "peer", "publicKey": priv.PublicKey().String(), "preSharedKey": psk.String(), "allowedIPs": []string{"10.0.0.2/32"}, "keepAlive": uint32(25)})
	if err != nil {
		t.Fatal(err)
	}
	account, err := u.Account.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	peer := account.(*wireguard.PeerConfig)
	if len(peer.PublicKey) != 64 || len(peer.PreSharedKey) != 64 || peer.Endpoint != "" || peer.KeepAlive != 25 {
		t.Fatalf("bad live peer: %v", peer)
	}
	if err := ValidateWireguardHotPeer(priv.PublicKey().String(), psk.String(), priv.String()); err != nil {
		t.Fatal(err)
	}
	if err := ValidateWireguardHotPeer(strings.Repeat("a", 44), "", ""); err == nil {
		t.Fatal("invalid key accepted")
	}
}
func TestHotShadowsocks2022UsesUserAccount(t *testing.T) {
	u, err := buildAPIUser("shadowsocks", map[string]any{"email": "ss", "password": "key", "cipher": "2022-blake3-aes-128-gcm"})
	if err != nil {
		t.Fatal(err)
	}
	account, err := u.Account.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := account.(*shadowsocks_2022.Account); !ok {
		t.Fatalf("not a user account: %T", account)
	}
}
