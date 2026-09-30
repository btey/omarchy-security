# SPDX-License-Identifier: MIT
CARGO   ?= cargo
QMLLINT ?= /usr/lib/qt6/bin/qmllint
OMARCHY_SHELL ?= $(or $(OMARCHY_PATH),/usr/share/omarchy)/shell

PREFIX  ?= /usr
DESTDIR ?=
LIBDIR  := $(PREFIX)/lib/omarchy-security
EBPF_DIR := crates/omarchy-security-ebpf
EBPF_OBJ := $(EBPF_DIR)/target/bpfel-unknown-none/release/exec-monitor

PLUGIN_SRC  := $(CURDIR)/plugins/security_hub
PLUGIN_DEST := $(HOME)/.config/omarchy/plugins/security-hub
QML_FILES   := $(shell find plugins/security_hub -name '*.qml' -not -path '*/tests/*')

.PHONY: all build release ebpf test test-rust test-js test-py test-e2e footprint lint fmt run mock install uninstall plugin-link plugin-unlink clean

all: build

build:
	$(CARGO) build --workspace

release:
	$(CARGO) build --workspace --release

# The eBPF exec monitor. Needs the nightly pinned in $(EBPF_DIR) and
# bpf-linker (`cargo install bpf-linker`), built against the system LLVM.
ebpf:
	cd $(EBPF_DIR) && $(CARGO) build --release

test: test-rust test-js test-py

test-rust:
	$(CARGO) test --workspace

test-js:
	node --test plugins/security_hub/tests/

test-py:
	python3 -m unittest discover -s tools -p 'test_*.py'

# Needs a Wayland session: loads the plugin in a private Quickshell instance.
test-e2e:
	OMARCHY_SHELL=$(OMARCHY_SHELL) tools/qml-e2e.sh

# Measures the installed daemon and helper (plan task 4.1): 60 s idle,
# then 30 s of read-only requests. Read-only; needs both services running.
footprint:
	tools/footprint.py

lint:
	$(CARGO) fmt --all -- --check
	cd $(EBPF_DIR) && $(CARGO) +stable fmt -- --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	@# qmllint resolves `qs.*` through a directory named qs, so point one at
	@# the Omarchy shell. Quickshell types are only partly visible to it, so
	@# its output is advisory.
	@tmp=$$(mktemp -d) && ln -s $(OMARCHY_SHELL) $$tmp/qs && \
	  $(QMLLINT) -I $$tmp $(QML_FILES) || true; rm -rf $$tmp

fmt:
	$(CARGO) fmt --all
	cd $(EBPF_DIR) && $(CARGO) +stable fmt

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

clean:
	$(CARGO) clean
	cd $(EBPF_DIR) && $(CARGO) clean
