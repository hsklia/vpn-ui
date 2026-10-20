#!/usr/bin/env python3
"""Validate a complete local release build without installing or starting it.

This checks the exact resource inputs used by go:embed and probes the final
panel's version. It does not claim to inspect every embedded byte in the final
ELF, start a service, or replace the isolated runtime continuity tests.
"""

import argparse
import datetime
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import tarfile


FLAT_FILES = (
    "xl2tpd", "xl2tpd-control", "openvpn", "pptpd", "pptpctrl", "ocserv",
    "ocserv-worker", "occtl", "telemt", "pptp", "openconnect", "vpnc-script",
    "sstp-pppd-plugin.so",
)
GEO_FILES = ("geoip.dat", "geosite.dat", "geoip_IR.dat", "geosite_IR.dat",
             "geoip_RU.dat", "geosite_RU.dat")
ARCHITECTURES = {"amd64": (62, "x86_64"), "arm64": (183, "aarch64")}
VERSION_PATTERN = re.compile(r"\d+(?:\.\d+)*\Z")
MAX_GLIBC = (2, 34)
ARCHIVES = {
    "pppd-bundle.tgz": ("usr/libexec/vpn-ui", (
        "sbin/pppd", "sbin/pppd.bin", "lib/pppd/*/radius.so",
        "lib/pppd/*/pppol2tp.so", "lib/ossl-modules/legacy.so")),
    "libreswan-bundle.tgz": ("usr/libexec/vpn-ui/libreswan", (
        "sbin/ipsec", "sbin/pluto", "libexec/ipsec/pluto.bin",
        "libexec/ipsec/certutil", "libexec/ipsec/certutil.bin",
        "lib/libsoftokn3.so", "lib/libfreeblpriv3.so")),
    "accel-ppp-bundle.tgz": ("usr/libexec/vpn-ui-accel", (
        "sbin/accel-pppd", "sbin/accel-pppd.bin", "bin/accel-cmd",
        "bin/accel-cmd.bin", "lib/accel-ppp/libsstp.so",
        "lib/accel-ppp/libradius.so", "share/accel-ppp/radius/dictionary")),
    "strongswan-bundle.tgz": ("usr/libexec/vpn-ui-strongswan", (
        "sbin/charon", "libexec/ipsec/charon.bin", "sbin/swanctl",
        "sbin/swanctl.bin", "bin/pki", "bin/pki.bin",
        "lib/ipsec/plugins/libstrongswan-eap-radius.so",
        "lib/ipsec/plugins/libstrongswan-eap-identity.so",
        "lib/ipsec/plugins/libstrongswan-kernel-netlink.so",
        "lib/ipsec/plugins/libstrongswan-vici.so")),
    "sstpc-bundle.tgz": ("usr/libexec/vpn-ui-sstpc", (
        "sbin/sstpc", "sbin/sstpc.bin", "lib/ossl-modules/legacy.so")),
}


class ValidationError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def run_command(args, *, cwd=None):
    env = os.environ.copy()
    # A version probe must not inherit the installed panel's paths or secrets.
    env = {key: value for key, value in env.items() if not key.startswith("VPNUI_")}
    env["GOTOOLCHAIN"] = "local"
    try:
        result = subprocess.run(args, cwd=cwd, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValidationError(f"cannot run {args[0]}: {error}") from error
    require(result.returncode == 0,
            f"command failed: {' '.join(map(str, args))}\n{result.stderr[-4096:]}")
    # Submodule status uses its leading byte to report pin agreement.
    return result.stdout.rstrip("\r\n")


def resource_record(path, root):
    require(path.is_file() and not path.is_symlink(), f"missing regular file: {path}")
    size = path.stat().st_size
    require(size > 0, f"empty release resource: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": path.relative_to(root).as_posix(), "size": size,
            "sha256": digest.hexdigest()}


def elf_header(data, arch, label, *, shared=False):
    require(len(data) >= 64 and data[:4] == b"\x7fELF", f"not an ELF: {label}")
    require(data[4] == 2 and data[5] == 1, f"not a 64-bit little-endian ELF: {label}")
    kind, machine = struct.unpack_from("<HH", data, 16)
    require(machine == ARCHITECTURES[arch][0], f"wrong ELF architecture: {label}")
    require(kind in ((3,) if shared else (2, 3)), f"wrong ELF type: {label}")
    return kind


def inspect_elf(path, arch, command, *, static=False, plugin=False):
    with path.open("rb") as handle:
        elf_header(handle.read(64), arch, str(path), shared=plugin)
    program_headers = command(["readelf", "-lW", str(path)])
    dynamic = command(["readelf", "-dW", str(path)])
    needed = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic)
    interpreter = bool(re.search(r"\bINTERP\b", program_headers))
    if static:
        require(not interpreter and not needed, f"must be statically linked: {path}")
    if plugin:
        require(not interpreter, f"plugin contains an executable interpreter: {path}")
        allowed = {f"libc.musl-{ARCHITECTURES[arch][1]}.so.1"}
        require(set(needed) <= allowed, f"plugin has unbundled dependencies: {path}: {needed}")
    return {"interpreter": interpreter, "needed": needed}


def inspect_glibc(path, command):
    versions = command(["readelf", "--version-info", "--wide", str(path)])
    require("GLIBC_PRIVATE" not in versions, "panel depends on private glibc symbols")
    required = sorted({tuple(map(int, value.split("."))) for value in
                       re.findall(r"\bGLIBC_(\d+(?:\.\d+)+)\b", versions)})
    if required:
        require(required[-1] <= MAX_GLIBC,
                f"panel requires GLIBC_{'.'.join(map(str, required[-1]))}; maximum is GLIBC_2.34")
    return [".".join(map(str, value)) for value in required]


def normalized_archive_path(name):
    require(not name.startswith("/"), f"absolute archive path: {name}")
    path = PurePosixPath(name)
    require(".." not in path.parts, f"parent traversal in archive: {name}")
    return path.as_posix().rstrip("/")


def link_target(member):
    require(not member.linkname.startswith("/"), f"absolute archive link: {member.name}")
    start = PurePosixPath(member.name).parent if member.issym() else PurePosixPath()
    parts = []
    for part in (start / member.linkname).parts:
        if part == "..":
            require(bool(parts), f"archive link escapes root: {member.name}")
            parts.pop()
        elif part != ".":
            parts.append(part)
    return "/".join(parts)


def inspect_archive(path, arch):
    prefix, anchors = ARCHIVES[path.name]
    loader = f"lib/ld-musl-{ARCHITECTURES[arch][1]}.so.1"
    files = {}
    headers = {}
    elf_count = 0
    try:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive:
                name = normalized_archive_path(member.name)
                in_prefix = name == prefix or name.startswith(prefix + "/")
                ancestor = member.isdir() and prefix.startswith(name + "/")
                require(in_prefix or ancestor, f"unexpected path in {path.name}: {name}")
                require(member.isdir() or member.isfile() or member.issym() or member.islnk(),
                        f"special archive entry: {path.name}:{name}")
                require(name not in files, f"duplicate archive entry: {path.name}:{name}")
                files[name] = member
                if member.issym() or member.islnk():
                    target = link_target(member)
                    require(target.startswith(prefix + "/"),
                            f"archive link escapes bundle: {path.name}:{name}")
                if member.isfile():
                    handle = archive.extractfile(member)
                    require(handle is not None, f"unreadable archive entry: {name}")
                    with handle:
                        header = handle.read(64)
                        headers[name] = header
                        if header.startswith(b"\x7fELF"):
                            elf_header(header, arch, f"{path.name}:{name}")
                            elf_count += 1
                        # Consume all bytes to detect truncated/corrupt members.
                        while handle.read(1024 * 1024):
                            pass
            # Also validate the gzip trailer, even after tar's end markers.
            while archive.fileobj.read(1024 * 1024):
                pass
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ValidationError(f"invalid archive {path}: {error}") from error
    resolved = {}
    for name, info in files.items():
        target = name
        if info.issym() or info.islnk():
            require(link_target(info) in files, f"dangling archive link: {path.name}:{name}")
            seen = {name}
            target = link_target(info)
            while files[target].issym() or files[target].islnk():
                require(target not in seen, f"cyclic archive link: {path.name}:{name}")
                seen.add(target)
                target = link_target(files[target])
                require(target in files, f"dangling archive link: {path.name}:{name}")
        resolved[name] = target
    for anchor in (*anchors, loader):
        pattern = prefix + "/" + anchor
        matches = [name for name, info in files.items() if fnmatch.fnmatchcase(name, pattern)
                   and (info.isfile() or info.issym() or info.islnk())]
        require(bool(matches), f"missing {pattern} in {path.name}")
        for name in matches:
            actual = files[resolved[name]]
            require(actual.isfile() and actual.size > 0,
                    f"empty required member {pattern} in {path.name}")
            header = headers[resolved[name]]
            if anchor.endswith(".bin") or ".so" in anchor:
                elf_header(header, arch, f"{path.name}:{name}", shared=".so" in anchor)
                if anchor.endswith(".bin") or anchor == loader:
                    require(actual.mode & stat.S_IXUSR,
                            f"required ELF is not executable: {path.name}:{name}")
            elif not anchor.startswith("share/"):
                require(header.startswith(b"#!") and actual.mode & stat.S_IXUSR,
                        f"required launcher is not an executable script: {path.name}:{name}")
    require(elf_count > 0, f"archive has no native ELF members: {path.name}")
    return {"prefix": prefix, "member_count": len(files), "elf_count": elf_count}


def inspect_geo_stamp(path):
    try:
        lines = path.read_text().splitlines()
        stamps = {}
        for line in lines:
            name, timestamp = line.split("\t")
            require(name not in stamps, f"duplicate geofile stamp: {name}")
            require(timestamp.isdigit() and int(timestamp) > 0, f"invalid geofile stamp: {line}")
            stamps[name] = int(timestamp)
    except (ValueError, UnicodeError) as error:
        raise ValidationError(f"invalid geo.stamp: {error}") from error
    require(set(stamps) == set(GEO_FILES), "geo.stamp must name exactly all six geofiles")
    return stamps


def verify_release(root, arch, command=run_command):
    require(arch in ARCHITECTURES, f"unsupported release architecture: {arch}")
    version = (root / "config/version").read_text().strip()
    require(VERSION_PATTERN.fullmatch(version), "config/version must be dotted numeric")
    command(["bash", str(root / "build/core/build.sh"), "--check-source"], cwd=root)
    git = lambda directory, *args: command(["git", "-C", str(directory), *args])
    panel_revision = git(root, "rev-parse", "HEAD")
    record = git(root, "ls-tree", "HEAD", "--", "third_party/Xray-core")
    match = re.fullmatch(r"160000 commit ([0-9a-f]{40,64})\tthird_party/Xray-core", record)
    require(match is not None, "panel HEAD does not record the core gitlink")
    core_revision = match.group(1)
    require(git(root / "third_party/Xray-core", "rev-parse", "HEAD") == core_revision,
            "core checkout does not match the panel gitlink")
    submodule_status = git(root, "submodule", "status", "--recursive")
    require(all(line.startswith(" ") for line in submodule_status.splitlines()),
            "recursive submodules are missing, conflicted or not at their recorded pins")
    require(not git(root, "diff", "--name-only", "HEAD", "--"),
            "release source contains tracked changes outside its recorded commit")

    backend = root / "backend/bin" / arch
    core = root / "corebundle/core"
    expected_backend = set(FLAT_FILES) | set(ARCHIVES)
    require(backend.is_dir(), f"missing backend resource directory: {backend}")
    require({entry.name for entry in backend.parent.iterdir()} - {".gitkeep"} == {arch},
            "backend embed root must contain only this release architecture")
    require({entry.name for entry in backend.iterdir()} == expected_backend,
            "backend resource directory must contain exactly the thirteen flat files and five bundles")
    require(core.is_dir(), "missing core embed resource directory")
    require({entry.name for entry in core.iterdir()} - {".gitkeep"}
            == set(GEO_FILES) | {"geo.stamp", arch},
            "core embed directory contains missing or unexpected resources")
    require((core / arch).is_dir() and {entry.name for entry in (core / arch).iterdir()}
            == {"xray", ".xray.commit"}, "core architecture directory has unexpected resources")
    resources = []
    archives = {}
    for name in FLAT_FILES:
        path = backend / name
        resources.append(resource_record(path, root))
        if name == "vpnc-script":
            require(path.read_bytes().startswith(b"#!"), "vpnc-script must be a shell script")
            command(["sh", "-n", str(path)])
        else:
            inspect_elf(path, arch, command, static=name != "sstp-pppd-plugin.so",
                        plugin=name == "sstp-pppd-plugin.so")
        if name != "sstp-pppd-plugin.so":
            require(path.stat().st_mode & stat.S_IXUSR, f"resource is not executable: {path}")
    for name in ARCHIVES:
        path = backend / name
        resources.append(resource_record(path, root))
        archives[name] = inspect_archive(path, arch)
    for name in GEO_FILES:
        resources.append(resource_record(core / name, root))
    resources.append(resource_record(core / "geo.stamp", root))
    stamps = inspect_geo_stamp(core / "geo.stamp")
    core_binary = core / arch / "xray"
    resources.append(resource_record(core_binary, root))
    inspect_elf(core_binary, arch, command, static=True)
    require(core_binary.stat().st_mode & stat.S_IXUSR, "core is not executable")
    marker = core / arch / ".xray.commit"
    resources.append(resource_record(marker, root))
    require(marker.read_text().strip() == core_revision, "core build marker does not match its source pin")
    require("xray" in command([str(core_binary), "-version"]).lower(), "core version probe failed")

    artifact = root / "build/out" / f"vpn-ui-{arch}"
    artifact_record = resource_record(artifact, root)
    require(artifact.stat().st_mode & stat.S_IXUSR, "panel artifact is not executable")
    linkage = inspect_elf(artifact, arch, command)
    glibc_versions = inspect_glibc(artifact, command)
    require(command([str(artifact), "-v"], cwd=root) == version,
            "panel artifact -v does not match config/version")
    return {
        "schema_version": 1, "architecture": arch, "version": version,
        "validated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "validation_scope": "complete source embed inputs, native ELF/linkage and exact panel version; runtime continuity is separate",
        "source": {"panel_revision": panel_revision, "core_revision": core_revision,
                   "recursive_submodules": submodule_status.splitlines()},
        "toolchain": {"go": command(["go", "version"], cwd=root),
                      "c_compiler": command([os.environ.get("CC", "cc"), "--version"]).splitlines()[0]},
        "artifact": artifact_record, "panel_linkage": linkage,
        "required_glibc_versions": glibc_versions, "maximum_allowed_glibc": "2.34",
        "resources": resources, "archive_checks": archives, "geo_stamps": stamps,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=sorted(ARCHITECTURES))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    try:
        manifest = verify_release(root, args.arch)
        output = args.output if args.output.is_absolute() else root / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(output.name + ".new")
        temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        temporary.replace(output)
    except (ValidationError, OSError, UnicodeError) as error:
        print(f"release validation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"validated": True, "architecture": args.arch,
                      "version": manifest["version"], "sha256": manifest["artifact"]["sha256"],
                      "manifest": str(output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
