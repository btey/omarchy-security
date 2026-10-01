# SPDX-License-Identifier: MIT
"""Tests for the plugin's backend installer and uninstaller (plan task 5.3,
§5.22): plugins/security_hub/backend/{install,uninstall}.sh, run against a
fake release in a temporary directory, with stub commands for sudo,
systemctl, pacman, ufw and nft."""

import hashlib
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "plugins" / "security_hub" / "backend"
INSTALL = BACKEND / "install.sh"
UNINSTALL = BACKEND / "uninstall.sh"
VERSION = re.search(
    r'"version":\s*"([^"]+)"', (ROOT / "plugins/security_hub/manifest.json").read_text()
).group(1)
ARCH = platform.machine()
TARBALL = f"omarchy-security-hub-{VERSION}-{ARCH}.tar.gz"

# Logs its name and arguments, one call per line, to $OMSEC_TEST_LOG.
LOGGER = '#!/bin/sh\necho "$(basename "$0") $*" >> "$OMSEC_TEST_LOG"\n'
# `pacman -T` lists what $OMSEC_TEST_MISSING names; `-Qqo` owns nothing
# unless $OMSEC_TEST_OWNER is set.
PACMAN = textwrap.dedent("""\
    #!/bin/sh
    echo "pacman $*" >> "$OMSEC_TEST_LOG"
    case "$1" in
    -T) shift; status=0
        for p in "$@"; do
          case " $OMSEC_TEST_MISSING " in *" $p "*) echo "$p"; status=127;; esac
        done
        exit $status;;
    -Qqo) [ -n "$OMSEC_TEST_OWNER" ] && { echo "$OMSEC_TEST_OWNER"; exit 0; }
        exit 1;;
    esac
    """)
# The release's Makefile, reduced to leaving a mark.
MAKEFILE = "install:\n\techo installed >> \"$$OMSEC_TEST_LOG\"\n"
# The source tree's Makefile: `ebpf` logs the variables that pick its
# toolchain, and fails when $OMSEC_TEST_EBPF_FAIL is set.
SOURCE_MAKEFILE = MAKEFILE + textwrap.dedent("""\
    release:
    \techo release >> "$$OMSEC_TEST_LOG"
    ebpf:
    \techo "ebpf RUSTC_BOOTSTRAP=$$RUSTC_BOOTSTRAP RUSTUP_TOOLCHAIN=$$RUSTUP_TOOLCHAIN" >> "$$OMSEC_TEST_LOG"
    \t[ -z "$$OMSEC_TEST_EBPF_FAIL" ]
    ebpf-toolchain:
    \t@echo nightly-test
    """)
# The commands a rustup install, or pacman's rust, would put on PATH.
RUST_COMMANDS = {"cargo", "rustc", "rustup", "bpf-linker"}


def makefile_uninstall_files():
    """The files the Makefile's uninstall target removes, with PREFIX=/usr."""
    text = (ROOT / "Makefile").read_text()
    recipe = text.split("\nuninstall:\n", 1)[1].split("\n\n", 1)[0]
    paths = re.findall(r"\$\(DESTDIR\)(\S+)", recipe.split("-rmdir", 1)[0])
    subst = {"$(PREFIX)": "/usr", "$(LIBDIR)": "/usr/lib/omarchy-security"}
    out = set()
    for p in paths:
        for k, v in subst.items():
            p = p.replace(k, v)
        out.add(p.rstrip("\\"))
    return out


def script_files():
    text = UNINSTALL.read_text()
    block = text.split("FILES=(", 1)[1].split(")", 1)[0]
    return {line.strip() for line in block.splitlines() if line.strip()}


class Env:
    """A temporary directory with a fake release, stub commands and a log."""

    def __init__(self, test):
        self.dir = Path(tempfile.mkdtemp(prefix="omsec-backend-"))
        test.addCleanup(shutil.rmtree, self.dir, True)
        self.log = self.dir / "log"
        self.log.touch()
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        for name in ("systemctl", "ufw", "nft"):
            self.stub(name, LOGGER)
        self.stub("pacman", PACMAN)
        self.release = self.dir / "release"
        self.release.mkdir()
        self.env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": str(self.dir / "home"),
            "XDG_CONFIG_HOME": str(self.dir / "home/.config"),
            "XDG_STATE_HOME": str(self.dir / "home/.local/state"),
            "OMSEC_TEST_LOG": str(self.log),
            "OMSEC_SUDO": "",
            "OMSEC_RELEASE_BASE": self.release.as_uri(),
        }

    def stub(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def make_release(self, checksum=None, listed=True):
        top = self.dir / "build" / f"omarchy-security-hub-{VERSION}"
        top.mkdir(parents=True)
        (top / "Makefile").write_text(MAKEFILE)
        with tarfile.open(self.release / TARBALL, "w:gz") as tar:
            tar.add(top, arcname=top.name)
        digest = checksum or hashlib.sha256((self.release / TARBALL).read_bytes()).hexdigest()
        name = TARBALL if listed else "another.tar.gz"
        (self.release / "SHA256SUMS").write_text(f"{digest}  {name}\n")

    def make_source(self):
        top = self.dir / "build" / f"omarchy-security-{VERSION}"
        top.mkdir(parents=True)
        (top / "Makefile").write_text(SOURCE_MAKEFILE)
        (top / "Cargo.toml").write_text("")
        source = self.dir / "source.tar.gz"
        with tarfile.open(source, "w:gz") as tar:
            tar.add(top, arcname=top.name)
        self.env["OMSEC_SOURCE_URL"] = source.as_uri()

    def without_rust(self):
        """PATH without the machine's Rust: the stubs, and the rest of
        /usr/bin through links."""
        sysbin = self.dir / "sysbin"
        sysbin.mkdir()
        for tool in Path("/usr/bin").iterdir():
            if tool.name not in RUST_COMMANDS:
                (sysbin / tool.name).symlink_to(tool)
        self.env["PATH"] = f"{self.bin}:{sysbin}"

    def run(self, script, *args, prefix=(), **env):
        return subprocess.run(
            [*prefix, str(script), *args],
            env={**self.env, **env},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def calls(self):
        return self.log.read_text().splitlines()


@unittest.skipUnless(ARCH == "x86_64", "releases have binaries for x86_64 only")
class InstallTests(unittest.TestCase):
    def test_installs_a_matching_release_and_enables_the_services(self):
        e = Env(self)
        e.make_release()
        r = e.run(INSTALL, "--yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("checksum OK", r.stdout)
        calls = e.calls()
        self.assertIn("installed", calls)
        after = calls[calls.index("installed"):]
        self.assertEqual(
            [c for c in after if c.startswith("systemctl")],
            [
                "systemctl daemon-reload",
                "systemctl enable omarchy-securityd-helper.service omarchy-security-firewall.service",
                "systemctl restart omarchy-securityd-helper.service",
                "systemctl enable --now pcscd.socket",
                "systemctl --user daemon-reload",
                "systemctl --user enable omarchy-securityd.service",
                "systemctl --user restart omarchy-securityd.service",
            ],
        )
        # USBGuard, ufw and the firewall mode are left alone.
        self.assertFalse([c for c in calls if c.startswith(("ufw", "systemctl")) and "usbguard" in c])
        self.assertFalse([c for c in calls if c.startswith("ufw")])

    def test_a_wrong_checksum_stops_before_installing(self):
        e = Env(self)
        e.make_release(checksum="0" * 64)
        r = e.run(INSTALL, "--yes")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does not match SHA256SUMS", r.stderr)
        self.assertNotIn("installed", e.calls())

    def test_an_unlisted_tarball_stops_before_installing(self):
        e = Env(self)
        e.make_release(listed=False)
        r = e.run(INSTALL, "--yes")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does not list", r.stderr)
        self.assertNotIn("installed", e.calls())

    def test_installs_missing_packages(self):
        e = Env(self)
        e.make_release()
        r = e.run(INSTALL, "--yes", OMSEC_TEST_MISSING="nftables usbguard")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("pacman -S --needed --noconfirm nftables usbguard", e.calls())

    def test_asks_first(self):
        e = Env(self)
        e.make_release()
        r = e.run(INSTALL)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("pass --yes", r.stderr)
        self.assertNotIn("installed", e.calls())

    def test_refuses_root(self):
        e = Env(self)
        e.make_release()
        r = e.run(INSTALL, "--yes", prefix=("unshare", "-r"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not as root", r.stderr)

    def test_refuses_an_install_from_a_package(self):
        e = Env(self)
        e.make_release()
        e.stub("omarchy-securityd", "#!/bin/sh\n")
        for script in (INSTALL, UNINSTALL):
            r = e.run(script, "--yes", OMSEC_TEST_OWNER="omarchy-security-hub")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("with pacman", r.stderr)
        self.assertNotIn("installed", e.calls())

    def test_destdir_installs_without_services(self):
        e = Env(self)
        e.make_release()
        r = e.run(INSTALL, "--yes", DESTDIR=str(e.dir / "stage"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("installed", e.calls())
        self.assertFalse([c for c in e.calls() if c.startswith("systemctl")])

    def test_rejects_a_bad_version(self):
        e = Env(self)
        r = e.run(INSTALL, "--yes", "--version", "1.0; rm -rf /")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not a version", r.stderr)



class SourceInstallTests(unittest.TestCase):
    """--from-source, with a source tree whose Makefile only logs."""

    def env(self, rustup):
        e = Env(self)
        e.make_source()
        e.without_rust()
        e.stub("bpf-linker", "#!/bin/sh\n")
        if rustup:
            e.stub("cargo", "#!/bin/sh\n")
            e.stub("rustup", '#!/bin/sh\n[ "$1 $2" = "toolchain list" ] && echo "$OMSEC_TEST_TOOLCHAINS"\n')
        return e

    def run_install(self, e, **env):
        return e.run(INSTALL, "--from-source", "--yes", DESTDIR=str(e.dir / "stage"),
                     OMSEC_TEST_MISSING="rust rust-src bpf-linker", RUSTUP_TOOLCHAIN="stable", **env)

    def test_without_rustup_uses_pacmans_rust(self):
        # Everything from the distribution: rust links the system LLVM, as
        # bpf-linker does, and RUSTC_BOOTSTRAP gives the BPF target build-std.
        e = self.env(rustup=False)
        r = self.run_install(e)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("pacman -S --needed --noconfirm bpf-linker rust rust-src", e.calls())
        self.assertIn("ebpf RUSTC_BOOTSTRAP=1 RUSTUP_TOOLCHAIN=", e.calls())
        self.assertEqual(e.calls()[-1], "installed")

    def test_with_rustup_uses_the_makefiles_nightly(self):
        e = self.env(rustup=True)
        r = self.run_install(e, OMSEC_TEST_TOOLCHAINS="nightly-test-x86_64-unknown-linux-gnu")
        self.assertEqual(r.returncode, 0, r.stderr)
        # Not pacman's rust, which conflicts with rustup; its bpf-linker.
        self.assertIn("pacman -S --needed --noconfirm bpf-linker", e.calls())
        # RUSTUP_TOOLCHAIN (from mise) would override the nightly.
        self.assertIn("ebpf RUSTC_BOOTSTRAP= RUSTUP_TOOLCHAIN=", e.calls())
        self.assertEqual(e.calls()[-1], "installed")

    def test_with_rustup_without_the_nightly_skips_ebpf(self):
        e = self.env(rustup=True)
        r = self.run_install(e, OMSEC_TEST_TOOLCHAINS="stable-x86_64-unknown-linux-gnu")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("rustup toolchain install nightly-test --component rust-src", r.stdout + r.stderr)
        self.assertFalse([c for c in e.calls() if c.startswith("ebpf")])
        self.assertEqual(e.calls()[-1], "installed")

    def test_a_failed_ebpf_build_still_installs(self):
        e = self.env(rustup=False)
        r = self.run_install(e, OMSEC_TEST_EBPF_FAIL="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("did not build", r.stdout + r.stderr)
        self.assertEqual(e.calls()[-1], "installed")


class UninstallTests(unittest.TestCase):
    def test_file_list_matches_the_makefile(self):
        self.assertEqual(script_files(), makefile_uninstall_files())

    def staged(self, e, mode):
        stage = e.dir / "stage"
        for f in script_files():
            p = stage / f.lstrip("/")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.touch()
        state = stage / "var/lib/omarchy-security"
        state.mkdir(parents=True)
        if mode:
            (state / "mode").write_text(mode + "\n")
        (state / "firewall.nft").touch()
        (state / "rules.json").touch()
        return stage, state

    def test_standalone_turns_ufw_back_on(self):
        e = Env(self)
        stage, state = self.staged(e, "standalone")
        r = e.run(UNINSTALL, "--yes", DESTDIR=str(stage))
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = e.calls()
        self.assertIn("ufw --force enable", calls)
        # ufw is on again before the hub's table goes.
        self.assertLess(calls.index("ufw --force enable"), calls.index("nft delete table inet omarchy_sec"))
        self.assertFalse((state / "mode").exists())
        self.assertFalse((state / "firewall.nft").exists())
        self.assertTrue((state / "rules.json").exists())
        self.assertEqual([f for f in script_files() if (stage / f.lstrip("/")).exists()], [])
        self.assertFalse((stage / "usr/lib/omarchy-security").exists())

    def test_ufw_mode_leaves_ufw_alone(self):
        for mode in ("ufw", None):
            e = Env(self)
            stage, _ = self.staged(e, mode)
            r = e.run(UNINSTALL, "--yes", DESTDIR=str(stage))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse([c for c in e.calls() if c.startswith("ufw")], mode)
            self.assertIn("nft delete table inet omarchy_sec", e.calls())

    def test_purge_deletes_state_and_configuration(self):
        e = Env(self)
        stage, state = self.staged(e, "ufw")
        config = e.dir / "home/.config/omarchy-security"
        user_state = e.dir / "home/.local/state/omarchy-security"
        for d in (config, user_state):
            d.mkdir(parents=True)
            (d / "x").touch()
        r = e.run(UNINSTALL, "--yes", DESTDIR=str(stage))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(config.exists() and user_state.exists() and state.exists())
        r = e.run(UNINSTALL, "--yes", "--purge", DESTDIR=str(stage))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(config.exists() or user_state.exists() or state.exists())


if __name__ == "__main__":
    unittest.main()
