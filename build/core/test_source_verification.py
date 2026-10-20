#!/usr/bin/env python3
"""Offline regression tests for the pinned-core build boundary.

Run: python3 -m unittest discover -s build/core -p 'test_*.py' -v
All repositories and generated artifacts are disposable. No real Go build,
download, submodule fetch, or release resource is used.
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


BUILD_SCRIPT = Path(__file__).with_name("build.sh")


class CoreSourceVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vpn-ui-core-source-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "panel"
        self.root.mkdir()
        (self.root / "build/core").mkdir(parents=True)
        shutil.copyfile(BUILD_SCRIPT, self.root / "build/core/build.sh")
        self.core = self.root / "third_party/Xray-core"
        self.core.mkdir(parents=True)
        self.env = os.environ.copy()
        for key in ("XRAY_SRC", "XRAY_REPO", "XRAY_REF", "XRAY_CACHE", "GEO_ONLY",
                    "CORE_FORCE", "GEO_FORCE", "GEO_LEAN", "FORCE_COLOR"):
            self.env.pop(key, None)
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        NO_COLOR="1", GEO_LEAN="1")
        self.git(self.root, "init", "-q")
        self.git(self.core, "init", "-q")
        (self.core / "go.mod").write_text("module example.invalid/test-core\n")
        (self.core / "main.go").write_text("package main\nfunc main() {}\n")
        self.git(self.core, "add", ".")
        self.commit(self.core, "initial core")
        self.pin = self.git(self.core, "rev-parse", "HEAD").strip()
        self.git(self.root, "add", "build", "third_party/Xray-core")
        self.commit(self.root, "record core pin")

        # Stubs make accidental builds/downloads observable without network or Go.
        self.bin = Path(self.temp.name) / "bin"
        self.bin.mkdir()
        self.trace = Path(self.temp.name) / "commands.log"
        self.env["TEST_BUILD_TRACE"] = str(self.trace)
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env["PATH"]
        self.stub("curl", """echo curl >> "$TEST_BUILD_TRACE"
if [[ "$1" == "-fsSIL" ]]; then
    printf 'Last-Modified: Tue, 20 Oct 2026 00:00:00 GMT\\n'
    exit 0
fi
while (( $# )); do
    if [[ "$1" == "-o" ]]; then printf fixture > "$2"; exit 0; fi
    shift
done
exit 1
""")
        self.stub("go", """echo go >> "$TEST_BUILD_TRACE"
while (( $# )); do
    if [[ "$1" == "-o" ]]; then
        printf '#!/bin/sh\\nexit 0\\n' > "$2"
        exit 0
    fi
    shift
done
exit 1
""")
        self.stub("stat", "printf '1792454400\\n'\n")

    def git(self, cwd, *args):
        result = subprocess.run(
            ["git", "-c", "user.name=Core source test", "-c",
             "user.email=core-test@example.invalid", "-c", "commit.gpgsign=false",
             "-c", "core.hooksPath=/dev/null", "-C", str(cwd), *args],
            env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=True,
        )
        return result.stdout

    def commit(self, cwd, message):
        self.git(cwd, "commit", "-qm", message)

    def stub(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/bash\nset -eu\n" + body)
        path.chmod(0o755)

    def run_script(self, *args, extra_env=None):
        env = self.env.copy()
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["bash", str(self.root / "build/core/build.sh"), *args],
            cwd=self.root, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )

    def assert_no_build_or_download(self):
        self.assertFalse(self.trace.exists(), "source validation invoked curl or Go")
        self.assertFalse((self.root / "corebundle").exists(),
                         "source validation created release output")

    def test_clean_recorded_core_passes_without_side_effects(self):
        result = self.run_script("--check-source")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified Xray source", result.stdout)
        self.assert_no_build_or_download()

    def test_missing_core_fails_before_download_without_fallback_clone(self):
        shutil.rmtree(self.core)
        result = self.run_script("amd64")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("git submodule update --init --recursive", result.stderr)
        self.assert_no_build_or_download()

    def test_parent_repository_cannot_masquerade_as_core(self):
        shutil.rmtree(self.core / ".git")
        result = self.run_script("--check-source")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not an initialized nested Git checkout", result.stderr)
        self.assert_no_build_or_download()

    def test_uncommitted_gitlink_update_is_rejected_even_when_staged(self):
        (self.core / "main.go").write_text("package main\nfunc main() { println(1) }\n")
        self.git(self.core, "add", "main.go")
        self.commit(self.core, "candidate core")
        self.git(self.root, "add", "third_party/Xray-core")
        result = self.run_script("--check-source")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match panel HEAD's pin", result.stderr)
        self.assert_no_build_or_download()
        self.commit(self.root, "reviewed core pin")
        result = self.run_script("--check-source")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_tracked_core_edits_are_rejected_staged_or_unstaged(self):
        (self.core / "main.go").write_text("package main\nfunc main() { println(2) }\n")
        for staged in (False, True):
            with self.subTest(staged=staged):
                if staged:
                    self.git(self.core, "add", "main.go")
                result = self.run_script("--check-source")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("tracked source changes", result.stderr)
                self.assert_no_build_or_download()

    def test_untracked_geo_fixture_requires_developer_override(self):
        (self.core / "geoip.dat").write_text("local geo fixture")
        result = self.run_script("--check-source")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("untracked or ignored files", result.stderr)
        self.assert_no_build_or_download()

    def test_untracked_go_source_is_rejected_before_cache_lookup(self):
        (self.core / "main").mkdir()
        (self.core / "main/extra.go").write_text("package main\nfunc init() {}\n")
        out = self.root / "corebundle/core/amd64"
        out.mkdir(parents=True)
        (out / "xray").write_text("#!/bin/sh\nexit 0\n")
        (out / "xray").chmod(0o755)
        marker = out / ".xray.commit"
        marker.write_text(self.pin + "\n")
        result = self.run_script("amd64")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("untracked or ignored files", result.stderr)
        self.assertFalse(self.trace.exists(), "invalid source invoked curl or Go")
        self.assertEqual(marker.read_text().strip(), self.pin)

    def test_ignored_go_source_is_rejected(self):
        (self.core / "main").mkdir()
        (self.core / "main/extra.go").write_text("package main\nfunc init() {}\n")
        (self.core / ".git/info/exclude").write_text("main/extra.go\n")
        self.git(self.core, "check-ignore", "-q", "main/extra.go")
        self.assertEqual(self.git(self.core, "status", "--porcelain"), "")
        result = self.run_script("--check-source")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("untracked or ignored files", result.stderr)
        self.assert_no_build_or_download()

    def test_plain_directory_not_accepted_as_developer_checkout(self):
        dev = Path(self.temp.name) / "not-a-checkout"
        dev.mkdir()
        (dev / "go.mod").write_text("module example.invalid/invalid\n")
        result = self.run_script("--check-source", extra_env={"XRAY_SRC": str(dev)})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be a Git checkout", result.stderr)
        self.assert_no_build_or_download()

    def test_developer_override_forces_build_and_cannot_poison_pin_cache(self):
        out = self.root / "corebundle/core/amd64"
        out.mkdir(parents=True)
        (out / "xray").write_text("#!/bin/sh\nexit 0\n")
        (out / "xray").chmod(0o755)
        marker = out / ".xray.commit"
        marker.write_text(self.pin + "\n")
        # A normal clean pinned checkout can use a matching commit marker.
        result = self.run_script("amd64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("go", self.trace.read_text().splitlines())
        (self.core / "main.go").write_text("package main\nfunc main() { println(3) }\n")
        for _ in range(2):
            self.trace.unlink()
            result = self.run_script("amd64", extra_env={"XRAY_SRC": str(self.core)})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("developer override", result.stderr)
            self.assertEqual(self.trace.read_text().splitlines().count("go"), 1)
            self.assertFalse(marker.exists())
        # Returning to the pin must rebuild rather than reuse the dirty override.
        self.git(self.core, "checkout", "--", "main.go")
        self.trace.unlink()
        result = self.run_script("amd64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.trace.read_text().splitlines().count("go"), 1)
        self.assertEqual(marker.read_text().strip(), self.pin)


if __name__ == "__main__":
    unittest.main()
