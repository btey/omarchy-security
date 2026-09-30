// SPDX-License-Identifier: GPL-3.0-or-later

//! Replays `seeds/<target>/*` through the fuzz checks on stable, so
//! `make test-fuzz` catches a regression without nightly or libFuzzer.
//! `cargo fuzz` starts from the same seeds.

use std::fs;
use std::path::Path;

fn replay(target: &str, check: fn(&[u8])) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("seeds")
        .join(target);
    let mut count = 0;
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        let data = fs::read(&path).unwrap();
        let outcome = std::panic::catch_unwind(|| check(&data));
        assert!(outcome.is_ok(), "{target}: {} fails", path.display());
        count += 1;
    }
    assert!(count > 0, "no seeds in {}", dir.display());
}

macro_rules! seeds {
    ($($target:ident),* $(,)?) => {
        $(#[test]
        fn $target() {
            replay(stringify!($target), omarchy_security_fuzz::$target);
        })*
    };
}

seeds!(
    rpc_frame,
    helper_request,
    usbguard_rule,
    token,
    exec_event,
    packet,
    kernel_log,
    ufw_tuple,
);
