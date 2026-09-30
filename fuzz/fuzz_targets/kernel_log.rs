// SPDX-License-Identifier: GPL-3.0-or-later
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| omarchy_security_fuzz::kernel_log(data));
