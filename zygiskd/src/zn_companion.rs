// src/zn_companion.rs

//! Companion process host for Zygisk Next (ZN) modules.
//!
//! Spawned on demand by the daemon (see `handle_spawn_zn_companion` in
//! `zygiskd.rs`), a ZN companion runs the module's `zn_companion_module`
//! entry point in a dedicated process forked from the privileged daemon,
//! instead of inside the (possibly restricted) target that loaded the module.
//!
//! Protocol on the control socket:
//! - The daemon writes the library path (string) and sends the library FD.
//! - This process replies with one byte: 1 = companion ready, 0 = failure.
//! - After that, module code inside targets sends a 1-byte command
//!   (`kCmdConnect = 1`) plus an FD via `SCM_RIGHTS` on the same socket for
//!   every `connectCompanion` call; each received FD is handed to
//!   `onModuleConnected`.

use crate::dl;
use crate::utils::UnixStreamExt;
use anyhow::{Context, Result};
use log::{debug, error, info, trace};
use passfd::FdPassingExt;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

/// The companion entry point exported by a Zygisk Next module, mirroring
/// `struct ZygiskNextCompanionModule` in `zygisk_next_api.h`.
#[repr(C)]
struct ZygiskNextCompanionModule {
    target_api_version: i32,
    on_companion_loaded: Option<unsafe extern "C" fn()>,
    on_module_connected: Option<unsafe extern "C" fn(i32)>,
}

/// Command byte sent by the module code when it calls `connectCompanion`.
const K_CMD_CONNECT: u8 = 1;

/// Control-message buffer aligned to `cmsghdr`; the kernel may copy the
/// header into it (see cmsg(3)).
#[repr(C)]
union HeaderAlignedBuf {
    buf: [libc::c_char; 64], // CMSG_SPACE(sizeof(int)) is tiny; 64 is plenty.
    align: libc::cmsghdr,
}

/// Entry point for a ZN companion process (`zygiskd zn-companion <fd>`).
pub fn entry(fd: i32) {
    info!("ZN companion process started with fd={}", fd);
    if let Err(e) = run_companion(fd) {
        error!("ZN companion process failed: {:?}", e);
    }
    info!("ZN companion process exiting.");
}

fn run_companion(fd: i32) -> Result<()> {
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };

    // 1. Receive the library path and its FD from the main daemon.
    let lib_path = stream.read_string().context("Failed to read library path")?;
    let library_fd = stream.recv_fd().context("Failed to receive library FD")?;

    // 2. Load the module library and resolve its companion entry point.
    let module = match load_companion_module(library_fd) {
        Ok(Some(m)) => m,
        Ok(None) => {
            debug!("`{}` does not export zn_companion_module", lib_path);
            // Signal that there's no entry point, then exit.
            stream.write_u8(0).context("Failed to send 'no entry' reply")?;
            return Ok(());
        }
        Err(e) => {
            // Signal failure and exit.
            stream.write_u8(0).context("Failed to send failure reply")?;
            return Err(e).context(format!("Failed to load `{}`", lib_path));
        }
    };

    let on_companion_loaded = match module.on_companion_loaded {
        Some(f) => f,
        None => {
            stream.write_u8(0)?;
            return Ok(());
        }
    };
    let on_module_connected = match module.on_module_connected {
        Some(f) => f,
        None => {
            stream.write_u8(0)?;
            return Ok(());
        }
    };

    // 3. Signal readiness back to the daemon.
    stream.write_u8(1).context("Failed to send success reply")?;
    info!("ZN companion serving {}", lib_path);

    // 4. Invoke the module's initialization callback.
    unsafe { on_companion_loaded() };

    // 5. Main loop: accept connect requests from the module code inside
    //    targets. Each request is a 1-byte command plus an FD (SCM_RIGHTS).
    loop {
        let mut cmd: u8 = 0;
        let mut iov = libc::iovec {
            iov_base: &mut cmd as *mut u8 as *mut libc::c_void,
            iov_len: 1,
        };
        let mut cmsg_buf = HeaderAlignedBuf { buf: [0; 64] };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = unsafe { cmsg_buf.buf.as_mut_ptr() } as *mut libc::c_void;
        msg.msg_controllen = 64;

        let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
        if n <= 0 {
            info!("ZN companion control socket closed, terminating");
            break;
        }
        if cmd != K_CMD_CONNECT {
            continue;
        }

        let mut client_fd = -1;
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !cmsg.is_null() {
            let hdr = unsafe { &*cmsg };
            if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_RIGHTS {
                client_fd = unsafe { *(libc::CMSG_DATA(cmsg) as *const i32) };
                break;
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        }
        if client_fd >= 0 {
            trace!("ZN companion connection on fd={}", client_fd);
            unsafe { on_module_connected(client_fd) };
        }
    }

    Ok(())
}

/// Loads a shared library from a file descriptor and resolves the ZN
/// companion symbol.
///
/// # Safety
/// This function calls `dlopen` and `dlsym`, which are unsafe FFI functions.
/// The provided `fd` must be a valid, open file descriptor to a shared library.
fn load_companion_module(fd: RawFd) -> Result<Option<ZygiskNextCompanionModule>> {
    let _owned_fd = unsafe { OwnedFd::from_raw_fd(fd) }; // Ensure FD is closed on scope exit.
    let path = format!("/proc/self/fd/{}", fd);

    unsafe {
        let handle = dl::dlopen(&path, libc::RTLD_NOW)?;
        let symbol = CString::new("zn_companion_module")?;
        let ptr = libc::dlsym(handle, symbol.as_ptr());
        if ptr.is_null() {
            Ok(None)
        } else {
            // The symbol points at the module's exported struct; copy it so
            // the function pointers stay valid after the handle is kept open.
            Ok(Some(std::ptr::read(ptr as *const ZygiskNextCompanionModule)))
        }
    }
}
