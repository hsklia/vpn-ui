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
- Ordinary `/addClient` requests involving WireGuard (C) or AmneziaWG now use
  targeted live activation after their normal authorization, reseller pricing
  and membership projection. This includes single and bulk creation. Exact
  retries resume a saved admission without replacing credentials or charging again.
- These legacy creations use the existing address pools. Insufficient capacity
  and memberships involving a protocol without live admission return an error
  rather than silently expanding ranges or requesting a shared restart.
- Existing account edits, deletions, other legacy protocol workflows and structural
  inbound/core changes keep their existing behavior; their restart semantics have
  not changed.
- Shadowsocks 2022 multi-user admission accepts the bundled core's supported AES
  GCM methods and rejects unsupported methods before persistence.

Stock native VLESS admission already supports live add when its API succeeds.
The ordinary WireGuard (C) creation workflow also requested a full reconcile and
a shared-core restart, even though its kernel peer update was additive. The legacy
creation path now uses the same incremental peer and live routing operations as
the explicit hot-add API, without running that full reconcile.

## Download and install a release

Operators do not need Go, Docker, or a source build. Download the binary matching
its host architecture from [published releases](https://github.com/hsklia/vpn-ui/releases),
verify `SHA256SUMS`, and use the existing panel's Overview → VPN-UI → Manual Update
→ Update from file flow. Preserve an independent database/executable/service
backup first. The upgrade replaces the same installation and restarts its panel
and supervised core once; it does not recreate users or reset configuration.

Version `1.9.4.2` includes the legacy creation fix and is recognized as newer than
`1.9.4.1` by the existing upload validator and update comparison.

If an ordinary create responds with `success: false` and `obj.persisted: true`,
the account was saved but live activation did not finish. Correct the reported
runtime problem and retry the exact original request. Its reservation stays in
place and the retry does not create another account or charge another sale.
Disabled accounts can be stored without a running core. An already expired
account must also have automatic renewal disabled to use this storage-only path.

## Automated build and release

[The release workflow](.github/workflows/release.yml) builds native Linux AMD64
and ARM64 artifacts from the exact checked-out commit and recorded submodule pins.
It performs a complete forced core/daemon build, resource completeness and ELF/libc
checks, targeted normal/race tests and real-core continuity, then attaches source
receipts and SHA-256 sums. It does not install anything on a VPN server.

Pull requests build/test without publishing. A numeric tag matching `config/version`
(or an explicit manual draft request) creates a **draft** release only after both
architecture jobs succeed. Assets are not overwritten on an existing published
release. Review and validate the exact downloaded artifacts before publishing the
draft; an incomplete build must never become the latest downloadable release.
Full integration tests against the exact release executable are an additional
publication gate, beyond source/service tests. Keep test credentials and databases
outside release assets.

## Developer build from this fork

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
`hsklia/vpn-ui` releases in this fork. A source commit alone does not create a release
asset. Only published, validated releases are downloadable through these paths;
a draft is not an update target. Failed downloads do not fall back to the stock
panel.

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
