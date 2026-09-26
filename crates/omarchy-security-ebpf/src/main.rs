// SPDX-License-Identifier: GPL-2.0-only

//! Exec monitor for omarchy-securityd-helper (task 2.2).
//!
//! It attaches to the `sched:sched_process_exec` tracepoint, which fires
//! once an `execve` has succeeded, so `/proc/<pid>/exe` already shows the
//! new image when userspace looks. The plan names `sys_enter_execve`, but
//! that fires before the kernel resolves anything, including for execs
//! that then fail.
//!
//! The program drops executions from root-owned system directories whose
//! path has no `/.` or `//` in it, which is most of them. Everything else
//! goes to userspace through the `EVENTS` ring buffer, and userspace makes
//! the final decision: it resolves relative paths, follows symlinks through
//! `/proc/<pid>/exe`, and recognises memfds.
//!
//! Event layout (native endian, 272 bytes), mirrored in the helper:
//!
//! | offset | field          |
//! |--------|----------------|
//! | 0      | `pid: u32`     |
//! | 4      | `uid: u32`     |
//! | 8      | `filename_len: u32` (bytes before the NUL) |
//! | 12     | reserved       |
//! | 16     | `filename: [u8; 256]` |

#![no_std]
#![no_main]

use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel_str_bytes,
};
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::{EbpfContext, Global};

const FILENAME_LEN: usize = 256;

#[repr(C)]
struct ExecEvent {
    pid: u32,
    uid: u32,
    filename_len: u32,
    reserved: u32,
    filename: [u8; FILENAME_LEN],
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Offset of the `__data_loc char[] filename` field in the tracepoint
/// record. The helper reads it from the tracepoint's `format` file and
/// overwrites this default before loading.
#[unsafe(no_mangle)]
static FILENAME_FIELD_OFFSET: Global<u32> = Global::new(8);

#[tracepoint]
pub fn exec_monitor(ctx: TracePointContext) -> u32 {
    let _ = try_exec(&ctx);
    0
}

fn starts_with(buf: &[u8; FILENAME_LEN], prefix: &[u8]) -> bool {
    let mut i = 0;
    while i < prefix.len() {
        if buf[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// True for a plain path under a root-owned system directory, which an
/// unprivileged user cannot plant a binary in or redirect with a symlink.
fn trusted(buf: &[u8; FILENAME_LEN], len: usize) -> bool {
    let system = starts_with(buf, b"/usr/")
        || starts_with(buf, b"/bin/")
        || starts_with(buf, b"/sbin/")
        || starts_with(buf, b"/lib/")
        || starts_with(buf, b"/opt/");
    if !system {
        return false;
    }
    let mut i = 0;
    while i < FILENAME_LEN - 1 {
        if i + 1 >= len {
            break;
        }
        if buf[i] == b'/' && (buf[i + 1] == b'.' || buf[i + 1] == b'/') {
            return false;
        }
        i += 1;
    }
    true
}

fn try_exec(ctx: &TracePointContext) -> Result<(), i64> {
    let field = FILENAME_FIELD_OFFSET.load() as usize;
    // SAFETY: the tracepoint record holds a u32 __data_loc at `field`.
    let loc: u32 = unsafe { ctx.read_at(field)? };
    let offset = (loc & 0xffff) as usize;

    let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) else {
        return Ok(());
    };
    let event = entry.as_mut_ptr();
    // SAFETY: `event` points at a reserved, exclusively owned ring buffer
    // slot, and `src` into the tracepoint record, read with a probe helper.
    let len = unsafe {
        let src = (ctx.as_ptr() as *const u8).add(offset);
        match bpf_probe_read_kernel_str_bytes(src, &mut (*event).filename) {
            Ok(name) => name.len(),
            Err(_) => {
                entry.discard(0);
                return Ok(());
            }
        }
    };
    // SAFETY: as above.
    let filename = unsafe { &(*event).filename };
    if trusted(filename, len) {
        entry.discard(0);
        return Ok(());
    }
    // SAFETY: as above.
    unsafe {
        (*event).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*event).uid = bpf_get_current_uid_gid() as u32;
        (*event).filename_len = len as u32;
        (*event).reserved = 0;
    }
    entry.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
