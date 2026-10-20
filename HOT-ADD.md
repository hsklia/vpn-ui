# Paired panel/core hot-add source

This fork maintains the source used by integration nodes to add one account or peer
without restarting the shared Xray core. It is based on vpn-ui 1.9.4
(`8044e0ad45c60149439546ea0fd99371a4d3c03d`) and preserves the supplied fork's
subsequent donation-address commit (`9b5b5b1d18a8999aedceb5ba1756fb15194c84e2`).

The paired core is maintained in [hsklia/Xray-core](https://github.com/hsklia/Xray-core).
The `third_party/Xray-core` gitlink records its exact commit. The core's Go module
and the panel's Go module retain their existing import identities; repository
hosting does not require renaming those modules.

## Scope

- Authenticated, administrator-only `addClientHot` and `addPeerHot` endpoints
  acknowledge `obj: {"applied": true, "noRestart": true}` only after live apply.
  See [api-reference.md](api-reference.md) for the request/response contract.
- Native accounts use the live core API. Classic WireGuard gains incremental core
  users. WireGuard (C) and AmneziaWG add missing peers to the existing kernel
  device. Account-derived routes are validated and replaced live.
- Failed hot admission returns an error; it never requests a restart as fallback.
  Retries preserve credentials and reconcile a lost successful response.
- Ordinary GUI/bulk/reseller mutations retain the existing upstream workflow.
  This change does **not** promise no restart for those paths or for structural
  inbound/core configuration changes.
- Shadowsocks 2022 multi-user admission accepts the bundled core's supported AES
  GCM methods and rejects unsupported methods before persistence.

Stock native VLESS admission already supports live add when its API succeeds.
The reproduced baseline restart cases were classic WireGuard and WireGuard (C)
admission; the production incident's exact protocol/configuration remains
unconfirmed. Kernel WG-C/AWG peer updates were already additive upstream; this
fix also applies their derived shared-core routes live.

## Build from this fork

Use an isolated **Linux** development/build host with Go 1.26.2, a C compiler
(SQLite uses CGO), Docker, Git, curl, and standard build tools. Do not build in the
directory of a running panel.

```sh
git clone --recurse-submodules https://github.com/hsklia/vpn-ui.git
cd vpn-ui
git rev-parse HEAD
git submodule status --recursive
./build.sh --force-core --arch amd64
```

The output is `build/out/vpn-ui-amd64`. Use `--arch arm64` on an ARM64 Linux build
host; cross-building requires the matching C cross compiler. Record the panel
commit, recursive submodule commits, toolchain version and output SHA-256 with
every artifact. Build reviewed commits, never a moving upstream branch.

The default core build requires the recorded, clean core submodule checkout.
Use `git submodule update --init --recursive` after checking out a different
panel commit. Do not use `--latest` for a release: it moves submodule pointers.
Explicit developer source overrides are not the release source of truth.

`--force-core` prevents reuse of an older core artifact. Do not use `--quick`,
`--skip-core`, `--skip-bundle`, or a plain `go build` for an installable release.
A plain panel build can compile with placeholder embed directories while lacking
the core and daemon bundles. The complete build must embed the patched core,
all six geofiles, and the daemon/client bundles, including the pinned telemt
submodule. Some upstream daemon recipes and geodata fetch moving dependencies;
pinning the Go source alone does not make the full binary bit-reproducible.

The panel installer, CLI updater, and dashboard release updater use
`hsklia/vpn-ui` releases in this fork. A source commit does not create a release
asset. With no fork release available, these paths fail rather than silently
download the stock panel. This work does not publish an installable binary.

## Verify the paired source

Build the core directly from this checkout for integration tests (this is a test
artifact, not the complete panel release):

```sh
go -C third_party/Xray-core build -trimpath -o /tmp/vpn-ui-xray-test ./main
python3 -c 'from pathlib import Path; Path("third_party/Xray-core/resources").mkdir(exist_ok=True)'
# Supply the core router suite's normal geosite.dat fixture under resources/.
go -C third_party/Xray-core test -race ./app/router/... ./proxy/wireguard
go test ./xray ./web/service
go test -race ./logger ./xray ./web/service ./web/controller -run '^(TestHot|TestConcurrentLog)' -count=1
VPNUI_HOT_ADD_TEST_BINARY=/tmp/vpn-ui-xray-test go test -race ./web/service -run '^TestHotClientLiveCore' -count=1
```

The last command is the real-core VLESS service test. The twelve-case native
matrix additionally requires the external `VPNUI_STAGE_NATIVE_RUNNER` and a
compatible Linux sing-box client; without those variables that opt-in test skips.
Use the integration harness scripts maintained in the integration repository’s `scripts/vpn-ui-hot-add/tests/` directory
for the native matrix and full panel → node → core HTTP test. Remove test-only
untracked/ignored fixtures (including downloaded `resources/*.dat`) before a
canonical release build; its source verifier intentionally rejects those files.

Earlier local synthetic staging of the same functional patches covered VLESS,
VMess, Trojan, Shadowsocks, Hysteria2, TUIC, classic WireGuard, kernel WireGuard
(C), and kernel AmneziaWG. It exercised held-open TCP/UDP streams, new-account
traffic, stable process identity, retries, invalid routing, and persistence.
Those runs used disposable local Linux environments, not production or a
dedicated staging server. They do not validate arbitrary production databases,
protocol combinations, or all upstream tests. Existing broad-suite failures
include a controller redirect-shape expectation and CPU-frequency sampling race;
targeted hot-add/routing tests are the relevant regression gates.

## Deployment boundary

This source publication performs no installation, service restart, or production
change. Automatic panel upgrade when clicking node update in a back-office
is not implemented by this fork.

A later in-place upgrade must preserve the existing database, keys, settings,
environment and service identity, retain a recoverable backup, verify the paired
artifact and running extracted core, and provide rollback. Loading the new
panel/core needs one planned restart. The no-restart behavior applies to
subsequent node-driven hot admissions. Update the paired panel/core before rolling
out a node that requires these endpoints; a new node with a stock panel rejects
new admissions rather than falling back to a restart.
