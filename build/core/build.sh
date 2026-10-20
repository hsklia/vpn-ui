#!/usr/bin/env bash
#
# build/core/build.sh — Build the pinned Xray core + fetch the geo data files
# that get embedded into the panel binary (go:embed) and extracted at runtime by
# the `corebundle` package.
#
# The panel ships a SPECIFIC patched Xray-core fork (hsklia/Xray-core) whose
# routing and account hot-add behavior the product depends on. This script
# produces that exact core, statically linked (CGO_ENABLED=0) so it runs on any
# Linux distro, and drops it, plus every geo file the routing editor can name,
# where the go:embed picks them up.
#
# Output layout (consumed by corebundle's //go:embed all:core):
#   corebundle/core/<goarch>/xray
#   corebundle/core/geoip.dat   geosite.dat            (base pair)
#   corebundle/core/geo{ip,site}_{IR,RU}.dat           (unless GEO_LEAN=1)
#
# Usage:
#   build/core/build.sh [goarch...]        # default: amd64
#   build/core/build.sh --check-source    # verify source only; no build/network
#
# Source of truth is the pinned submodule third_party/Xray-core (@ a fixed
# commit recorded in the panel's HEAD). Missing, modified, untracked (including
# ignored) or mismatched source is rejected. Initialize the recorded submodule
# rather than cloning a branch tip.
#
# Env:
#   XRAY_SRC   explicit developer checkout override (always rebuilt; no cache)
#   GEO_ONLY=1 only refresh geo files, skip the core build
#   GEO_LEAN=1 embed ONLY geoip.dat + geosite.dat, dropping the ~118MB of country
#              files geo{ip,site}_{IR,RU}.dat. The panel then downloads whichever
#              one a routing rule needs, the first time it needs it.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_ROOT="$REPO_ROOT/corebundle/core"

# shellcheck source=../lib/log.sh
source "$REPO_ROOT/build/lib/log.sh" 2>/dev/null || { step(){ echo "==> $*"; }; ok(){ echo "  - $*"; }; info(){ echo "  $*"; }; warn(){ echo "  ! $*" >&2; }; err(){ echo "  x $*" >&2; }; hr(){ :; }; }

CHECK_SOURCE=0
if [[ "${1:-}" == "--check-source" ]]; then
    CHECK_SOURCE=1
    shift
    if (( $# )); then
        err "--check-source does not accept architecture arguments"
        exit 1
    fi
fi
ARCHES=("${@:-amd64}")

# --- base geo files (architecture-independent) ---------------------------------
# Same source the dashboard's "Update geofiles" uses (Loyalsoldier/v2ray-rules-dat),
# so the bundled fallback matches what a later dashboard update would fetch.
# Download one geo file ONLY when it changed. `-z <cached>` sends a conditional
# request (If-Modified-Since the cached file's mtime); the server answers 304 and
# no body when it's current, so we keep the cache and skip the ~14MB transfer. A
# fetch failure keeps the existing copy (geo is a runtime-updatable fallback).
# GEO_FORCE=1 always re-downloads.
_geo_one() {
    local url="$1" out="$2" tmp rc=0
    if [[ "${GEO_FORCE:-0}" != "1" && -s "$out" ]]; then
        tmp="$(mktemp)"
        curl -fsSL --retry 3 -z "$out" -o "$tmp" "$url" || rc=$?
        if [[ $rc -eq 0 && -s "$tmp" ]]; then
            mv "$tmp" "$out"; ok "$(basename "$out"): updated"
        elif [[ $rc -eq 0 ]]; then
            rm -f "$tmp"; info "$(basename "$out"): up to date (304) — skipped"
        else
            rm -f "$tmp"; warn "$(basename "$out"): check failed (rc=$rc) — keeping cached copy"
        fi
    else
        curl -fL --retry 3 -o "$out" "$url"; ok "$(basename "$out"): fetched"
    fi
}

# Every geo data file the panel's routing editor can name, and the complete set
# `corebundle` embeds. It is exactly the six the Basic Routing lists reference:
# `geoip:`/`geosite:` shorthands resolve to the Loyalsoldier pair, and the
# Iran/Russia entries are explicit `ext:geoip_IR.dat:ir` style references
# (web/html/xray.html settingsData). Keep this list in sync with
# `builtinGeofiles` in web/service/geofile.go, which is what the panel downloads
# from at runtime.
#
# All six are fetched and embedded by DEFAULT. The four country files add ~118MB
# (geosite_RU.dat alone is ~74MB) on top of the ~28MB base pair, which is a
# deliberate trade: the servers this panel runs on are frequently the ones that
# cannot reach GitHub at runtime, and a geo file the core cannot open is a fatal
# config parse error that takes every inbound down, not a degraded rule.
# GEO_LEAN=1 keeps only the base pair for a smaller binary; the panel then
# downloads a country file the first time a rule needs it (web/service/geofile.go).
GEO_BASE_FILES=(
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat|geoip.dat"
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat|geosite.dat"
)
GEO_COUNTRY_FILES=(
    "https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat|geoip_IR.dat"
    "https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat|geosite_IR.dat"
    "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat|geoip_RU.dat"
    "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat|geosite_RU.dat"
)

_geo_batch() {
    local entry url name
    for entry in "$@"; do
        url="${entry%%|*}"
        name="${entry#*|}"
        _geo_one "$url" "$OUT_ROOT/$name"
        _geo_stamp "$url" "$OUT_ROOT/$name"
    done
}

# Set the local file's mtime to the upstream Last-Modified, rather than leaving it
# at "whenever curl happened to write it".
#
# This is what makes the panel's own updater honest. The panel asks upstream
# `If-Modified-Since: <local mtime>`, and geo files reach a user pre-extracted from
# the binary, where the mtime would otherwise be the INSTALL time. Data built in
# March and installed in June would then look newer than every release in between,
# so the server answers 304, the panel reports "updated successfully", and the
# stale data stays. It never self-corrects either: GitHub's 304 carries an ETag but
# no Last-Modified, so there is nothing for the panel to re-stamp from.
_geo_stamp() {
    local url="$1" out="$2" lm
    [[ -e "$out" ]] || return 0
    lm="$(curl -fsSIL --retry 2 "$url" 2>/dev/null | grep -i '^last-modified:' | tail -1 | sed 's/^[Ll]ast-[Mm]odified:[[:space:]]*//' | tr -d '\r' || true)"
    if [[ -z "$lm" ]]; then
        warn "$(basename "$out"): upstream sent no Last-Modified; leaving mtime as-is"
        return 0
    fi
    if touch -d "$lm" "$out" 2>/dev/null; then
        ok "$(basename "$out"): dated $lm"
    else
        warn "$(basename "$out"): could not parse Last-Modified '$lm'; leaving mtime as-is"
    fi
}

# The embed drops file mtimes, so record them beside the data. corebundle reads
# this back and re-applies each date to the file it extracts, which is the whole
# point of _geo_stamp above.
write_geo_manifest() {
    local f name manifest="$OUT_ROOT/geo.stamp"
    : > "$manifest"
    for f in "$OUT_ROOT"/*.dat; do
        [[ -e "$f" ]] || continue
        name="$(basename "$f")"
        printf '%s\t%s\n' "$name" "$(stat -c %Y "$f")" >> "$manifest"
    done
    info "geo.stamp: $(wc -l < "$manifest") entries"
}

fetch_geo() {
    local entry name stale=()
    step "Checking geo files (conditional; GEO_FORCE=1 to force a refresh)"
    _geo_batch "${GEO_BASE_FILES[@]}"

    if [[ "${GEO_LEAN:-0}" == "1" ]]; then
        # Left behind by an earlier full build. They would still be embedded, so
        # remove them rather than let GEO_LEAN=1 quietly produce a ~118MB-fat binary.
        for entry in "${GEO_COUNTRY_FILES[@]}"; do
            name="${entry#*|}"
            if [[ -e "$OUT_ROOT/$name" ]]; then
                rm -f "$OUT_ROOT/$name"
                stale+=("$name")
            fi
        done
        if (( ${#stale[@]} )); then
            warn "GEO_LEAN=1: removed country geo files from a previous build: ${stale[*]}"
        fi
        info "GEO_LEAN=1: country geo files are NOT embedded; the panel downloads them on demand"
    else
        _geo_batch "${GEO_COUNTRY_FILES[@]}"
    fi

    # `|| true` on both: this script runs under `set -o pipefail`, so if the glob
    # matches nothing (a first run whose downloads all failed) the ls exits non-zero,
    # the pipeline inherits it, and the build dies here instead of at the real
    # failure. Same trap the submodule-status check documents above.
    write_geo_manifest
    info "geo: $(du -ch "$OUT_ROOT"/*.dat 2>/dev/null | tail -1 | awk '{print $1}' || true) across $(ls -1 "$OUT_ROOT"/*.dat 2>/dev/null | wc -l || true) file(s)"
    { ls -lh "$OUT_ROOT"/*.dat 2>/dev/null || true; } | awk '{print "    " $5, $9}'
}

# --- the pinned core -----------------------------------------------------------
prepare_src() {
    local src gitroot record expected actual untracked
    if [[ -n "${XRAY_SRC:-}" ]]; then
        src="$XRAY_SRC"
    else
        src="$REPO_ROOT/third_party/Xray-core"
    fi
    if [[ ! -f "$src/go.mod" ]]; then
        err "Xray source is missing at $src; run git submodule update --init --recursive" >&2
        return 1
    fi
    src="$(cd "$src" && pwd -P)"
    gitroot="$(git -C "$src" rev-parse --show-toplevel 2>/dev/null)" || {
        err "Xray source must be a Git checkout: $src" >&2
        return 1
    }
    # An uninitialized submodule directory otherwise resolves to the parent Git
    # repository, making its panel commit look like a valid core cache key.
    if [[ "$(cd "$gitroot" && pwd -P)" != "$src" ]]; then
        err "Xray source is not an initialized nested Git checkout: $src" >&2
        return 1
    fi
    if [[ -n "${XRAY_SRC:-}" ]]; then
        warn "XRAY_SRC developer override: bypassing the panel pin; core caching is disabled" >&2
        echo "$src"
        return
    fi
    record="$(git -C "$REPO_ROOT" ls-tree HEAD -- third_party/Xray-core)"
    if [[ "$record" != "160000 commit "* ]]; then
        err "Panel HEAD does not record the Xray core submodule" >&2
        return 1
    fi
    expected="${record#160000 commit }"
    expected="${expected%%$'\t'*}"
    actual="$(git -C "$src" rev-parse HEAD)"
    if [[ "$actual" != "$expected" ]]; then
        err "Xray core HEAD $actual does not match panel HEAD's pin $expected; initialize the recorded submodule or commit the reviewed pin update" >&2
        return 1
    fi
    if ! git -C "$src" diff --quiet HEAD --; then
        err "Xray core has tracked source changes; commit them and the panel pin, or use XRAY_SRC for an explicit developer build" >&2
        return 1
    fi
    # Do not use --exclude-standard: ignored Go, assembly, C or embedded files
    # can still change the compiled program and poison an approved-SHA cache.
    untracked="$(git -C "$src" ls-files --others)" || return 1
    if [[ -n "$untracked" ]]; then
        err "Xray core has untracked or ignored files; remove them from the release checkout, or use XRAY_SRC for an explicit developer build" >&2
        return 1
    fi
    echo "$src"
}

build_core() {
    local src="$1"
    # The commit the source is at. If the cached xray was built from this same
    # commit, there is nothing to rebuild — skip the (slow) go build. Bump the
    # submodule/ref to trigger a rebuild, or set CORE_FORCE=1.
    local srccommit
    srccommit="$(git -C "$src" rev-parse HEAD 2>/dev/null || echo unknown)"
    info "pinned Xray core source: $src @ ${srccommit:0:12}"
    for goarch in "${ARCHES[@]}"; do
        local outdir="$OUT_ROOT/$goarch"
        mkdir -p "$outdir"
        local marker="$outdir/.xray.commit"
        if [[ -z "${XRAY_SRC:-}" && "${CORE_FORCE:-0}" != "1" && -x "$outdir/xray" && "$srccommit" != "unknown" \
              && "$(cat "$marker" 2>/dev/null)" == "$srccommit" ]]; then
            ok "core ($goarch) already built from ${srccommit:0:12} — skipping (CORE_FORCE=1 to rebuild)"
            continue
        fi
        # Invalidate before building, including developer overrides: a failed or
        # dirty override build must not leave a valid pinned-source cache marker.
        rm -f "$marker"
        step "go build xray ($goarch, CGO_ENABLED=0, static)"
        ( cd "$src" && \
          CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
          go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -v -o "$outdir/xray" ./main )
        chmod 0755 "$outdir/xray"
        if [[ -z "${XRAY_SRC:-}" ]]; then
            echo "$srccommit" > "$marker"
        fi
        file "$outdir/xray" || true
        ok "core: $(ls -lh "$outdir/xray" | awk '{print $5, $9}')"
    done
}

if [[ "$CHECK_SOURCE" == "1" || "${GEO_ONLY:-0}" != "1" ]]; then
    CORE_SRC="$(prepare_src)"
    if [[ "$CHECK_SOURCE" == "1" ]]; then
        info "verified Xray source: $CORE_SRC"
        exit 0
    fi
fi
mkdir -p "$OUT_ROOT"
fetch_geo
if [[ "${GEO_ONLY:-0}" != "1" ]]; then
    build_core "$CORE_SRC"
fi
step "Done. Embed contents:"
ls -lhR "$OUT_ROOT"
