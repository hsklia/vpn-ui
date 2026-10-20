#!/usr/bin/env python3
"""Offline release-validator regressions; no Go compilation or network access."""

import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import tarfile
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("release_verify", Path(__file__).with_name("verify.py"))
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


def elf(arch="amd64", kind=2):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, kind, verify.ARCHITECTURES[arch][0], 1)
    struct.pack_into("<HHHHHH", header, 52, 64, 56, 0, 64, 0, 0)
    return bytes(header)


def write_file(path, contents, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contents)
    path.chmod(0o755 if executable else 0o644)


def archive_entries(name, arch="amd64"):
    prefix, anchors = verify.ARCHIVES[name]
    entries = {}
    for anchor in (*anchors, f"lib/ld-musl-{verify.ARCHITECTURES[arch][1]}.so.1"):
        member = prefix + "/" + anchor.replace("*", "2.5.2")
        if ".so" in member or member.endswith(".bin"):
            entries[member] = elf(arch, kind=3 if ".so" in member else 2)
        else:
            entries[member] = b"#!/bin/sh\nexit 0\n"
    return entries


def write_archive(path, entries, links=(), modes=None):
    with tarfile.open(path, "w:gz") as archive:
        for name, contents in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(contents)
            info.mode = (modes or {}).get(name, 0o755)
            archive.addfile(info, io.BytesIO(contents))
        for name, target in links:
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            archive.addfile(info)


class FakeCommands:
    def __init__(self, root, arch):
        self.root, self.arch = root, arch
        self.panel_revision = "a" * 40
        self.core_revision = "b" * 40
        self.actual_core_revision = self.core_revision
        self.submodule_prefix = " "
        self.version = "1.9.4.1"
        self.glibc = "2.34"
        self.dynamic_file = None
        self.plugin_needed = None
        self.calls = []

    def __call__(self, args, *, cwd=None):
        self.calls.append(list(args))
        if args[0] == "bash":
            return "verified core source"
        if args[0] == "git":
            operation = args[3:]
            if operation == ["rev-parse", "HEAD"]:
                return (self.actual_core_revision if Path(args[2]).name == "Xray-core"
                        else self.panel_revision)
            if operation[:1] == ["ls-tree"]:
                return f"160000 commit {self.core_revision}\tthird_party/Xray-core"
            if operation == ["submodule", "status", "--recursive"]:
                return (self.submodule_prefix + self.core_revision + " third_party/Xray-core\n"
                        + " " + "c" * 40 + " third_party/telemt")
            if operation[:1] == ["diff"]:
                return ""
        if args[0] == "readelf":
            name = Path(args[-1]).name
            if args[1] == "-lW":
                return "INTERP" if name.startswith("vpn-ui-") else "no program interpreter"
            if args[1] == "-dW":
                if name == self.dynamic_file:
                    return "(NEEDED) Shared library: [libc.so.6]"
                if name == "sstp-pppd-plugin.so":
                    needed = self.plugin_needed or f"libc.musl-{verify.ARCHITECTURES[self.arch][1]}.so.1"
                    return f"(NEEDED) Shared library: [{needed}]"
                return ""
            if args[1] == "--version-info":
                return f"Name: GLIBC_2.2.5\nName: GLIBC_{self.glibc}"
        if args[0] == "sh" and args[1] == "-n":
            return ""
        if args == ["go", "version"]:
            return f"go version go1.26.2 linux/{self.arch}"
        if args[-1] == "--version":
            return "cc fixture compiler"
        if args[-1] == "-version":
            return "Xray fixture core"
        if args[-1] == "-v":
            return self.version
        raise AssertionError(f"unexpected external command: {args}")


class ReleaseValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vpn-ui-release-validation-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.arch = "amd64"
        self.seed(self.arch)

    def seed(self, arch):
        self.arch = arch
        self.commands = FakeCommands(self.root, arch)
        shutil.rmtree(self.root / "corebundle", ignore_errors=True)
        shutil.rmtree(self.root / "backend", ignore_errors=True)
        self.backend = self.root / "backend/bin" / arch
        self.backend.mkdir(parents=True, exist_ok=True)
        write_file(self.root / "config/version", b"1.9.4.1\n")
        for name in verify.FLAT_FILES:
            contents = (b"#!/bin/sh\nexit 0\n" if name == "vpnc-script"
                        else elf(arch, 3 if name.endswith(".so") else 2))
            write_file(self.backend / name, contents, executable=not name.endswith(".so"))
        for name in verify.ARCHIVES:
            write_archive(self.backend / name, archive_entries(name, arch))
        self.core = self.root / "corebundle/core"
        for name in verify.GEO_FILES:
            write_file(self.core / name, b"synthetic geodata fixture")
        self.stamp = self.core / "geo.stamp"
        self.stamp.write_text("".join(name + "\t1792454400\n" for name in verify.GEO_FILES))
        write_file(self.core / arch / "xray", elf(arch), executable=True)
        write_file(self.core / arch / ".xray.commit", (self.commands.core_revision + "\n").encode())
        write_file(self.root / "build/out" / f"vpn-ui-{arch}", elf(arch), executable=True)

    def validate(self):
        return verify.verify_release(self.root, self.arch, self.commands)

    def test_complete_amd64_records_exact_inputs_and_provenance(self):
        result = self.validate()
        self.assertEqual(result["version"], "1.9.4.1")
        self.assertEqual(result["source"]["core_revision"], self.commands.core_revision)
        self.assertEqual(len(result["resources"]), 27)
        self.assertEqual(len(result["archive_checks"]), 5)
        self.assertIn("2.34", result["required_glibc_versions"])
        self.assertEqual(result["artifact"]["sha256"], verify.hashlib.sha256(elf()).hexdigest())
        json.dumps(result)

    def test_complete_arm64_is_validated_natively(self):
        self.seed("arm64")
        result = self.validate()
        self.assertEqual(result["architecture"], "arm64")
        self.assertIn([str(self.core / "arm64/xray"), "-version"], self.commands.calls)

    def test_missing_flat_binary_is_rejected(self):
        (self.backend / "ocserv-worker").unlink()
        with self.assertRaisesRegex(verify.ValidationError, "exactly the thirteen"):
            self.validate()

    def test_missing_pppd_bundle_is_rejected(self):
        (self.backend / "pppd-bundle.tgz").unlink()
        with self.assertRaisesRegex(verify.ValidationError, "exactly the thirteen"):
            self.validate()

    def test_extra_backend_input_is_rejected(self):
        (self.backend / "unexpected.log").write_text("build diagnostic")
        with self.assertRaisesRegex(verify.ValidationError, "exactly the thirteen"):
            self.validate()

    def test_unrecorded_second_architecture_cannot_enter_embed_tree(self):
        (self.backend.parent / "arm64").mkdir()
        with self.assertRaisesRegex(verify.ValidationError, "only this release architecture"):
            self.validate()

    def test_empty_resource_is_rejected(self):
        (self.backend / "occtl").write_bytes(b"")
        with self.assertRaisesRegex(verify.ValidationError, "empty release resource"):
            self.validate()

    def test_wrong_architecture_is_rejected(self):
        (self.backend / "telemt").write_bytes(elf("arm64"))
        with self.assertRaisesRegex(verify.ValidationError, "wrong ELF architecture"):
            self.validate()

    def test_dynamic_flat_executable_is_rejected(self):
        self.commands.dynamic_file = "openvpn"
        with self.assertRaisesRegex(verify.ValidationError, "statically linked"):
            self.validate()

    def test_plugin_must_be_shared_and_have_only_bundled_dependencies(self):
        self.commands.plugin_needed = "libsstp_api-0.so"
        with self.assertRaisesRegex(verify.ValidationError, "unbundled dependencies"):
            self.validate()
        self.commands.plugin_needed = None
        (self.backend / "sstp-pppd-plugin.so").write_bytes(elf(kind=2))
        with self.assertRaisesRegex(verify.ValidationError, "wrong ELF type"):
            self.validate()

    def test_geo_manifest_must_have_exact_unique_six_entries(self):
        original = self.stamp.read_text()
        for content in (original + "geoip.dat\t1792454400\n", original.splitlines()[0] + "\n"):
            with self.subTest(content=content):
                self.stamp.write_text(content)
                with self.assertRaises(verify.ValidationError):
                    self.validate()

    def test_core_marker_must_match_recorded_source(self):
        (self.core / self.arch / ".xray.commit").write_text("d" * 40)
        with self.assertRaisesRegex(verify.ValidationError, "build marker"):
            self.validate()

    def test_changed_submodule_and_core_pin_are_rejected(self):
        self.commands.submodule_prefix = "+"
        with self.assertRaisesRegex(verify.ValidationError, "recursive submodules"):
            self.validate()
        self.commands.submodule_prefix = " "
        self.commands.actual_core_revision = "d" * 40
        with self.assertRaisesRegex(verify.ValidationError, "core checkout"):
            self.validate()

    def test_final_artifact_version_must_equal_config(self):
        self.commands.version = "1.9.4"
        with self.assertRaisesRegex(verify.ValidationError, "-v does not match"):
            self.validate()

    def test_glibc_newer_than_supported_baseline_is_rejected(self):
        self.commands.glibc = "2.35"
        with self.assertRaisesRegex(verify.ValidationError, "maximum is GLIBC_2.34"):
            self.validate()

    def test_release_version_suffix_is_rejected(self):
        (self.root / "config/version").write_text("1.9.4-hot-add")
        with self.assertRaisesRegex(verify.ValidationError, "dotted numeric"):
            self.validate()

    def test_archive_without_required_module_is_rejected(self):
        name = "accel-ppp-bundle.tgz"
        entries = archive_entries(name)
        del entries["usr/libexec/vpn-ui-accel/lib/accel-ppp/libsstp.so"]
        write_archive(self.backend / name, entries)
        with self.assertRaisesRegex(verify.ValidationError, "missing .*libsstp"):
            self.validate()

    def test_archive_wrong_architecture_is_rejected(self):
        name = "sstpc-bundle.tgz"
        entries = archive_entries(name)
        entries["usr/libexec/vpn-ui-sstpc/sbin/sstpc.bin"] = elf("arm64")
        write_archive(self.backend / name, entries)
        with self.assertRaisesRegex(verify.ValidationError, "wrong ELF architecture"):
            self.validate()

    def test_required_archive_binary_cannot_be_a_nonempty_html_page(self):
        name = "sstpc-bundle.tgz"
        entries = archive_entries(name)
        entries["usr/libexec/vpn-ui-sstpc/sbin/sstpc.bin"] = b"<html>not a binary</html>"
        write_archive(self.backend / name, entries)
        with self.assertRaisesRegex(verify.ValidationError, "not an ELF"):
            self.validate()

    def test_required_archive_launcher_must_be_a_script(self):
        name = "sstpc-bundle.tgz"
        entries = archive_entries(name)
        entries["usr/libexec/vpn-ui-sstpc/sbin/sstpc"] = b"not a shell launcher"
        write_archive(self.backend / name, entries)
        with self.assertRaisesRegex(verify.ValidationError, "not an executable script"):
            self.validate()

    def test_required_archive_binary_and_loader_must_be_executable(self):
        name = "sstpc-bundle.tgz"
        prefix = verify.ARCHIVES[name][0]
        for member in (prefix + "/sbin/sstpc.bin", prefix + "/lib/ld-musl-x86_64.so.1"):
            with self.subTest(member=member):
                write_archive(self.backend / name, archive_entries(name), modes={member: 0o644})
                with self.assertRaisesRegex(verify.ValidationError, "required ELF is not executable"):
                    self.validate()

    def test_extra_core_embed_input_is_rejected(self):
        (self.core / "unrelated.log").write_text("not a release resource")
        with self.assertRaisesRegex(verify.ValidationError, "core embed directory"):
            self.validate()

    def test_archives_reject_traversal_and_escaping_or_dangling_links(self):
        name = "sstpc-bundle.tgz"
        path = self.backend / name
        prefix = verify.ARCHIVES[name][0]
        for extra, links in (({"../outside": b"x"}, ()),
                             ({"/absolute": b"x"}, ()),
                             ({}, ((prefix + "/escape", "../../../../etc/passwd"),)),
                             ({}, ((prefix + "/missing", "absent"),))):
            with self.subTest(extra=extra, links=links):
                entries = archive_entries(name)
                entries.update(extra)
                write_archive(path, entries, links)
                with self.assertRaises(verify.ValidationError):
                    verify.inspect_archive(path, self.arch)
        self.assertFalse((self.root / "outside").exists())

    def test_corrupt_archive_trailer_is_rejected(self):
        path = self.backend / "sstpc-bundle.tgz"
        data = bytearray(path.read_bytes())
        data[-1] ^= 0xFF
        path.write_bytes(data)
        with self.assertRaisesRegex(verify.ValidationError, "invalid archive"):
            verify.inspect_archive(path, self.arch)

    def test_command_output_preserves_submodule_status_prefix(self):
        output = verify.run_command(["sh", "-c", "printf ' abc\\n'"])
        self.assertEqual(output, " abc")


if __name__ == "__main__":
    unittest.main()
