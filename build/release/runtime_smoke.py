#!/usr/bin/env python3
"""Boot the exact release artifact only inside an offline disposable container."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

GEO_FILES = ("geoip.dat", "geosite.dat", "geoip_IR.dat", "geosite_IR.dat",
             "geoip_RU.dat", "geosite_RU.dat")


def require_disposable() -> None:
    """Reject host execution and any externally connected runtime namespace."""
    if sys.platform != "linux" or not Path("/.dockerenv").is_file():
        raise RuntimeError("Use a disposable Linux Docker container with --network none")
    fallback = {"tunl0", "gre0", "gretap0", "erspan0", "ip_vti0", "ip6_vti0",
                "sit0", "ip6tnl0", "ip6gre0"}
    for entry in Path("/sys/class/net").iterdir():
        if not (entry / "ifindex").is_file():
            continue
        if entry.name == "lo":
            continue
        if entry.name not in fallback or int((entry / "flags").read_text().strip(), 0) & 1:
            raise RuntimeError("The smoke container must have only loopback connectivity")
    for line in Path("/proc/net/route").read_text().splitlines()[1:]:
        if line.split() and line.split()[0] != "lo":
            raise RuntimeError("Unexpected non-loopback IPv4 route")
    for line in Path("/proc/net/ipv6_route").read_text().splitlines():
        if line.split() and line.split()[-1] != "lo":
            raise RuntimeError("Unexpected non-loopback IPv6 route")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def core_identity(binary: Path) -> tuple[int, str]:
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if Path(os.readlink(entry / "exe")) != binary:
                continue
            arguments = (entry / "cmdline").read_bytes().split(b"\0")
            if arguments[1:2] != [b"-c"]:
                continue
            # Start time is field 22, following the final ')' in the comm field.
            start = (entry / "stat").read_text().rsplit(") ", 1)[1].split()[19]
            found.append((int(entry.name), start))
        except (OSError, IndexError):
            continue
    if len(found) != 1:
        raise RuntimeError(f"Expected one extracted running core, found {len(found)}")
    return found[0]


def seed_settings(database: Path) -> None:
    """Keep the disposable install offline and avoid installing any host daemon."""
    settings = {
        "webListen": "127.0.0.1", "webPort": "28083", "webBasePath": "/",
        "webDomain": "", "webCertFile": "", "webKeyFile": "",
        "geofileAutoUpdate": "false", "subEnable": "false", "subJsonEnable": "false",
        "vpnProvisioned": "true", "provisionedProtocols": "[]",
    }
    connection = sqlite3.connect(database)
    try:
        for key, value in settings.items():
            changed = connection.execute("UPDATE settings SET value=? WHERE key=?", (value, key))
            if changed.rowcount == 0:
                connection.execute("INSERT INTO settings (key,value) VALUES (?,?)", (key, value))
        connection.commit()
    finally:
        connection.close()


def verify(source: Path, arch: str) -> dict:
    require_disposable()
    version = (source / "config/version").read_text().strip()
    binary = source / "build/out" / f"vpn-ui-{arch}"
    expected = {f"xray-linux-{arch}": source / "corebundle/core" / arch / "xray"}
    expected.update({name: source / "corebundle/core" / name for name in GEO_FILES})
    expected_hashes = {name: digest(path) for name, path in expected.items()}
    environment = {key: value for key, value in os.environ.items() if not key.startswith("VPNUI_")}
    process = None
    with tempfile.TemporaryDirectory(prefix="vpn-ui-release-smoke-", dir="/tmp") as name:
        work = Path(name)
        for folder in ("db", "bin", "log"):
            (work / folder).mkdir(mode=0o700)
        environment.update(VPNUI_DB_FOLDER=str(work / "db"), VPNUI_BIN_FOLDER=str(work / "bin"),
                           VPNUI_LOG_FOLDER=str(work / "log"), VPNUI_LOG_LEVEL="error")
        with (work / "private.log").open("wb") as log:
            setup = subprocess.run(
                [str(binary), "setting", "-username", "release-smoke", "-password",
                 secrets.token_urlsafe(24), "-port", "28083", "-listenIP", "127.0.0.1",
                 "-webBasePath", "/"],
                cwd=work, env=environment, stdout=log, stderr=subprocess.STDOUT,
                timeout=60, check=False,
            )
            if setup.returncode:
                raise RuntimeError("The release executable failed disposable database setup")
            seed_settings(work / "db/vpn-ui.db")
            try:
                process = subprocess.Popen([str(binary), "run"], cwd=work, env=environment,
                                           stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                deadline = time.monotonic() + 90
                while True:
                    if process.poll() is not None:
                        raise RuntimeError("The release executable exited during startup")
                    try:
                        with opener.open("http://127.0.0.1:28083/login", timeout=1) as response:
                            if response.status == 200:
                                break
                    except (OSError, urllib.error.URLError):
                        pass
                    if time.monotonic() >= deadline:
                        raise RuntimeError("The release HTTP listener did not become ready")
                    time.sleep(0.1)
                actual_hashes = {name: digest(work / "bin" / name) for name in expected_hashes}
                if actual_hashes != expected_hashes:
                    raise RuntimeError("Extracted release core/geodata differ from approved build inputs")
                core = work / "bin" / f"xray-linux-{arch}"
                core_version = subprocess.run([str(core), "-version"], env=environment,
                                              capture_output=True, text=True, timeout=15, check=True)
                if "xray" not in core_version.stdout.lower():
                    raise RuntimeError("Extracted core version probe failed")
                while True:
                    try:
                        original = core_identity(core)
                        break
                    except RuntimeError:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)
                time.sleep(2)
                if process.poll() is not None or core_identity(core) != original:
                    raise RuntimeError("The extracted core did not remain stable")
                return {"status": "PASS", "version": version, "architecture": arch,
                        "artifact_sha256": digest(binary), "http_ready": True,
                        "running_extracted_core_stable": True, "extracted_sha256": actual_hashes,
                        "scope": "Exact release startup and embedded core/geofile hashes; no host installation"}
            finally:
                if process is not None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=10)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--arch", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = verify(arguments.source.resolve(), arguments.arch)
        arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps(result, sort_keys=True))
    except (OSError, RuntimeError, subprocess.SubprocessError, sqlite3.Error) as error:
        print(f"release runtime smoke failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
