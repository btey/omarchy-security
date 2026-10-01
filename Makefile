# SPDX-License-Identifier: MIT
CARGO   ?= cargo
QMLLINT ?= /usr/lib/qt6/bin/qmllint
QMLFORMAT ?= /usr/lib/qt6/bin/qmlformat
OMARCHY_SHELL ?= $(or $(OMARCHY_PATH),/usr/share/omarchy)/shell

PREFIX  ?= /usr
DESTDIR ?=
LIBDIR  := $(PREFIX)/lib/omarchy-security
EBPF_DIR := crates/omarchy-security-ebpf
EBPF_OBJ := $(EBPF_DIR)/target/bpfel-unknown-none/release/exec-monitor
# cargo fuzz needs nightly; the eBPF crate's pin serves both.
FUZZ_TOOLCHAIN ?= nightly-2026-09-30
FUZZ_TARGETS := rpc_frame helper_request usbguard_rule token exec_event packet kernel_log ufw_tuple
FUZZ_SECS ?= 60

PLUGIN_SRC  := $(CURDIR)/plugins/security_hub
PLUGIN_DEST := $(HOME)/.config/omarchy/plugins/security-hub
QML_FILES   := $(shell find plugins/security_hub -name '*.qml' -not -path '*/tests/*')
# Cargo.toml is not in the release tarball, whose Makefile only installs.
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml 2>/dev/null)
DIST_NAME := omarchy-security-hub-$(VERSION)
DIST_DIR  := target/dist
PLUGIN_VALIDATE ?= $(or $(OMARCHY_PATH),/usr/share/omarchy)/bin/omarchy-plugin-validate
# Tarballs are stamped with the last commit's time, so a rebuild of the same
# commit gives the same files.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || date +%s)
TAR := tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@$(SOURCE_DATE_EPOCH)
# Extra arguments for the Rust test binaries; CI passes --nocapture so that
# tests which skip themselves show it.
RUST_TEST_ARGS ?=

.PHONY: all build release ebpf test test-rust test-js test-py test-fuzz test-e2e fuzz footprint system-check lint qml-check fmt run mock install uninstall plugin-link plugin-unlink plugin-install dist version-check clean

all: build

build:
	$(CARGO) build --workspace

release:
	$(CARGO) build --workspace --release

# The eBPF exec monitor. Needs the nightly pinned in $(EBPF_DIR) and
# bpf-linker (`cargo install bpf-linker`), built against the system LLVM.
ebpf:
	cd $(EBPF_DIR) && $(CARGO) build --release

test: test-rust test-js test-py test-fuzz

test-rust:
	$(CARGO) test --workspace -- $(RUST_TEST_ARGS)

test-js:
	node --test plugins/security_hub/tests/

test-py:
	python3 -m unittest discover -s tools -p 'test_*.py'

# Replays fuzz/seeds through the fuzz checks, on stable (plan task 4.5).
test-fuzz:
	cd fuzz && $(CARGO) +stable test -- $(RUST_TEST_ARGS)

# Fuzzes each parser that reads untrusted input for FUZZ_SECS seconds
# (plan task 4.5). Needs `cargo install cargo-fuzz` and the nightly above.
# New inputs go to fuzz/corpus, crashes to fuzz/artifacts (both ignored).
fuzz:
	cd fuzz && for t in $(FUZZ_TARGETS); do \
	  mkdir -p corpus/$$t && \
	  $(CARGO) +$(FUZZ_TOOLCHAIN) fuzz run -O $$t corpus/$$t seeds/$$t -- \
	    -max_total_time=$(FUZZ_SECS) -max_len=70000 || exit 1; \
	done

# Needs a Wayland session: loads the plugin in a private Quickshell instance.
test-e2e:
	OMARCHY_SHELL=$(OMARCHY_SHELL) tools/qml-e2e.sh

# End-to-end check of the installed hub (plan task 4.4): interactive, uses
# sudo for some checks, and undoes each test action. ARGS go to the script,
# e.g. ARGS="--only firewall,modes --other-host 192.168.1.20".
system-check:
	tools/system_check.py $(ARGS)

# Measures the installed daemon and helper (plan task 4.1): 60 s idle,
# then 30 s of read-only requests. Read-only; needs both services running.
footprint:
	tools/footprint.py

lint: qml-check
	$(CARGO) fmt --all -- --check
	cd $(EBPF_DIR) && $(CARGO) +stable fmt -- --check
	cd fuzz && $(CARGO) +stable fmt -- --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	cd fuzz && $(CARGO) +stable clippy --lib --tests -- -D warnings
	@# qmllint resolves `qs.*` through a directory named qs, so point one at
	@# the Omarchy shell. Quickshell types are only partly visible to it, so
	@# its output is advisory.
	@tmp=$$(mktemp -d) && ln -s $(OMARCHY_SHELL) $$tmp/qs && \
	  $(QMLLINT) -I $$tmp $(QML_FILES) || true; rm -rf $$tmp

# Strict syntax check of the plugin's QML and of the JS it imports (not the
# Node tests). qmlformat parses each file without resolving imports, so it
# needs neither Quickshell nor the Omarchy shell.
qml-check:
	@status=0; for f in $$(find plugins/security_hub -name '*.qml' -o -name '*.js' -not -path '*/tests/*'); do \
	  $(QMLFORMAT) "$$f" >/dev/null || { echo "qml-check: $$f does not parse" >&2; status=1; }; \
	done; exit $$status

fmt:
	$(CARGO) fmt --all
	cd $(EBPF_DIR) && $(CARGO) +stable fmt
	cd fuzz && $(CARGO) +stable fmt

run:
	RUST_LOG=$${RUST_LOG:-debug} $(CARGO) run -p omarchy-securityd

mock:
	tools/mock-securityd.py

# System install (run `make release ebpf` first, as your user). Without the
# eBPF object the threat module falls back to scanning /proc.
install:
	install -Dm755 target/release/omarchy-securityd $(DESTDIR)$(PREFIX)/bin/omarchy-securityd
	install -Dm755 target/release/omarchy-securityd-helper $(DESTDIR)$(LIBDIR)/omarchy-securityd-helper
	install -Dm755 tools/secctl.py $(DESTDIR)$(PREFIX)/bin/omarchy-secctl
	@if [ -f $(EBPF_OBJ) ]; then \
	  install -Dm644 $(EBPF_OBJ) $(DESTDIR)$(LIBDIR)/exec-monitor.bpf.o; \
	else echo "note: $(EBPF_OBJ) not built (make ebpf); installing without the eBPF exec monitor"; fi
	install -Dm644 dist/systemd/user/omarchy-securityd.service $(DESTDIR)$(PREFIX)/lib/systemd/user/omarchy-securityd.service
	install -Dm644 dist/systemd/system/omarchy-securityd-helper.service $(DESTDIR)$(PREFIX)/lib/systemd/system/omarchy-securityd-helper.service
	install -Dm644 dist/systemd/system/omarchy-security-firewall.service $(DESTDIR)$(PREFIX)/lib/systemd/system/omarchy-security-firewall.service
	install -Dm644 dist/polkit/org.omarchy.security.policy $(DESTDIR)$(PREFIX)/share/polkit-1/actions/org.omarchy.security.policy
	install -Dm644 dist/polkit/50-omarchy-security.rules $(DESTDIR)$(PREFIX)/share/polkit-1/rules.d/50-omarchy-security.rules
	install -Dm644 dist/config.example.toml $(DESTDIR)$(PREFIX)/share/doc/omarchy-security/config.example.toml

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/omarchy-securityd \
	  $(DESTDIR)$(PREFIX)/bin/omarchy-secctl \
	  $(DESTDIR)$(LIBDIR)/omarchy-securityd-helper \
	  $(DESTDIR)$(LIBDIR)/exec-monitor.bpf.o \
	  $(DESTDIR)$(PREFIX)/lib/systemd/user/omarchy-securityd.service \
	  $(DESTDIR)$(PREFIX)/lib/systemd/system/omarchy-securityd-helper.service \
	  $(DESTDIR)$(PREFIX)/lib/systemd/system/omarchy-security-firewall.service \
	  $(DESTDIR)$(PREFIX)/share/polkit-1/actions/org.omarchy.security.policy \
	  $(DESTDIR)$(PREFIX)/share/polkit-1/rules.d/50-omarchy-security.rules \
	  $(DESTDIR)$(PREFIX)/share/doc/omarchy-security/config.example.toml
	-rmdir $(DESTDIR)$(LIBDIR) $(DESTDIR)$(PREFIX)/share/doc/omarchy-security

# Development install: symlink the plugin into Omarchy's third-party plugin
# directory. It lands disabled; enable it with `omarchy plugin enable security-hub`.
plugin-link:
	@if [ -e "$(PLUGIN_DEST)" ] && [ ! -L "$(PLUGIN_DEST)" ]; then \
	  echo "$(PLUGIN_DEST) exists and is not a symlink; refusing to replace it" >&2; exit 1; fi
	mkdir -p $(dir $(PLUGIN_DEST))
	ln -sfn $(PLUGIN_SRC) $(PLUGIN_DEST)
	-omarchy-shell shell rescanPlugins

plugin-unlink:
	@if [ -L "$(PLUGIN_DEST)" ]; then rm "$(PLUGIN_DEST)"; else echo "no plugin symlink at $(PLUGIN_DEST)"; fi
	-omarchy-shell shell rescanPlugins

# Copies the plugin (without its tests) into Omarchy's plugin directory, for
# an install from a release tarball. It replaces an earlier copy or the
# development symlink, but nothing else.
plugin-install:
	@if [ -e "$(PLUGIN_DEST)" ] && [ ! -L "$(PLUGIN_DEST)" ] && \
	  ! grep -q '"id": "security-hub"' "$(PLUGIN_DEST)/manifest.json" 2>/dev/null; then \
	  echo "$(PLUGIN_DEST) exists and is not the Security Hub plugin; refusing to replace it" >&2; exit 1; fi
	@stage=$(dir $(PLUGIN_DEST)).security-hub.new && rm -rf $$stage && mkdir -p $$stage && \
	  tar -C plugins/security_hub --exclude=./tests -cf - . | tar -C $$stage -xf - && \
	  rm -rf $(PLUGIN_DEST) && mv $$stage $(PLUGIN_DEST)
	@echo "installed the plugin in $(PLUGIN_DEST)"
	-omarchy-shell shell rescanPlugins

# The crates, the eBPF crate and the plugin manifest carry one version. With
# TAG set (CI, on a tag push), it must be v<version>.
version-check:
	@test "$$(sed -n 's/^version = "\(.*\)"/\1/p' $(EBPF_DIR)/Cargo.toml)" = "$(VERSION)" || \
	  { echo "$(EBPF_DIR)/Cargo.toml is not at $(VERSION)" >&2; exit 1; }
	@grep -q '"version": "$(VERSION)"' plugins/security_hub/manifest.json || \
	  { echo "plugins/security_hub/manifest.json is not at $(VERSION)" >&2; exit 1; }
	@grep -q '^## $(VERSION) ' CHANGELOG.md || \
	  { echo "CHANGELOG.md has no section for $(VERSION)" >&2; exit 1; }
	@if [ -n "$(TAG)" ] && [ "$(TAG)" != "v$(VERSION)" ]; then \
	  echo "tag $(TAG) does not match version $(VERSION)" >&2; exit 1; fi
	@echo "version $(VERSION)"

# Release tarballs (plan task 5.2), after `make release ebpf`:
#   $(DIST_NAME)-x86_64.tar.gz  the built binaries, eBPF object, units, polkit
#                               files, CLI and plugin, installed from the
#                               unpacked directory with `sudo make install`
#                               and `make plugin-install`
#   security-hub-$(VERSION).tar.gz  the plugin alone, unpacked into
#                               ~/.config/omarchy/plugins
#   SHA256SUMS
# The plugin is checked with Omarchy's own `omarchy-plugin-validate`.
dist: version-check
	@for f in target/release/omarchy-securityd target/release/omarchy-securityd-helper $(EBPF_OBJ); do \
	  test -f $$f || { echo "$$f is missing; run make release ebpf" >&2; exit 1; }; done
	rm -rf $(DIST_DIR) && mkdir -p $(DIST_DIR)/$(DIST_NAME) $(DIST_DIR)/plugin/security-hub
	tar -cf - --exclude=./tests -C plugins/security_hub . | tar -xf - -C $(DIST_DIR)/plugin/security-hub
	$(PLUGIN_VALIDATE) $(DIST_DIR)/plugin/security-hub
	tar -cf - --exclude=plugins/security_hub/tests Makefile README.md CHANGELOG.md LICENSE LICENSES \
	  dist docs tools/secctl.py plugins/security_hub \
	  target/release/omarchy-securityd target/release/omarchy-securityd-helper $(EBPF_OBJ) | \
	  tar -xf - -C $(DIST_DIR)/$(DIST_NAME)
	cd $(DIST_DIR) && $(TAR) -czf $(DIST_NAME)-$(shell uname -m).tar.gz $(DIST_NAME) && \
	  $(TAR) -czf security-hub-$(VERSION).tar.gz -C plugin security-hub && \
	  rm -rf $(DIST_NAME) plugin && sha256sum *.tar.gz > SHA256SUMS
	@cat $(DIST_DIR)/SHA256SUMS

clean:
	$(CARGO) clean
	cd $(EBPF_DIR) && $(CARGO) clean
	cd fuzz && $(CARGO) +stable clean
