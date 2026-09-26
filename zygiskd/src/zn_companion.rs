// src/zn_companion.rs
//! Companion process entry for Zygisk Next (ZN) modules.
//! Mirrors companion.rs but speaks the ZygiskNextCompanionModule C ABI
//! (target_api_version / onCompanionLoaded / onModuleConnected) instead of
//! the standard zygisk_companion_entry(int) ABI.

use crate::dl;
use crate::utils::{UnixStreamExt, is_socket_alive};
use anyhow::{Context, Result};
use log::{debug, error, info, trace};
use passfd::FdPassingExt;
use std::ffi::{CString, c_int};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::thread;

/// Must exactly match `struct ZygiskNextCompanionModule` in zygisk_next_api.h.
#[repr(C)]
struct ZnCompanionModule {
    #[allow(dead_code)]
    target_api_version: c_int,
    on_companion_loaded: Option<unsafe extern "C" fn()>,
    on_module_connected: Option<unsafe extern "C" fn(fd: c_int)>,
}

/// Entry point when the daemon is re-exec'd as `zn-companion <lib_path> <fd>`.
pub fn entry(lib_path: &str, fd: i32) {
    info!("ZN companion process started for `{}`, fd={}", lib_path, fd);
    if let Err(e) = run_zn_companion(lib_path, fd) {
        error!("ZN companion process failed: {:?}", e);
    }
    info!("ZN companion process exiting.");
}

fn run_zn_companion(lib_path: &str, fd: i32) -> Result<()> {
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };

    let module = match load_zn_companion(lib_path) {
        Ok(Some(m)) => {
            debug!("ZN companion entry point found for `{}`", lib_path);
            stream.write_u8(1).context("Failed to send success reply")?;
            m
        }
        Ok(None) => {
            debug!("ZN module `{}` has no companion entry point.", lib_path);
            stream.write_u8(0).context("Failed to send 'no entry' reply")?;
            return Ok(());
        }
        Err(e) => {
            stream.write_u8(0).context("Failed to send failure reply")?;
            return Err(e).context(format!("Failed to load ZN companion `{}`", lib_path));
        }
    };

    if let Some(on_loaded) = module.on_companion_loaded {
        unsafe {
            on_loaded();
        }
    }

    // Main loop: each incoming client fd from the daemon is one connectCompanion() call
    // from a module instance running inside some target app.
    loop {
        if !is_socket_alive(&stream) {
            info!(
                "Daemon socket closed, terminating ZN companion for `{}`.",
                lib_path
            );
            break;
        }

        let client_fd = stream.recv_fd().context("Failed to receive client FD")?;
        trace!(
            "New ZN companion request for `{}` on fd={}",
            lib_path, client_fd
        );

        let on_connected = module.on_module_connected;
        thread::spawn(move || {
            if let Some(cb) = on_connected {
                // onModuleConnected owns and must close this fd itself (per ZN API contract).
                unsafe {
                    cb(client_fd);
                }
            } else {
                unsafe {
                    libc::close(client_fd);
                }
            }
        });
    }

    Ok(())
}

/// Loads the ZN module's .so from disk and resolves `zn_companion_module`.
///
/// # Safety
/// Reads a raw exported C struct across FFI; the on-disk library is trusted
/// module content, matching the trust model of the standard companion loader.
fn load_zn_companion(lib_path: &str) -> Result<Option<ZnCompanionModuleRef>> {
    unsafe {
        let handle = dl::dlopen(lib_path, libc::RTLD_NOW)?;
        let symbol = CString::new("zn_companion_module")?;
        let sym_ptr = libc::dlsym(handle, symbol.as_ptr());
        if sym_ptr.is_null() {
            return Ok(None);
        }
        let module = &*(sym_ptr as *const ZnCompanionModule);
        Ok(Some(ZnCompanionModuleRef {
            on_companion_loaded: module.on_companion_loaded,
            on_module_connected: module.on_module_connected,
        }))
    }
}

/// Plain-data copy of the two callbacks so they can be moved into the accept loop
/// without holding a raw pointer across threads.
struct ZnCompanionModuleRef {
    on_companion_loaded: Option<unsafe extern "C" fn()>,
    on_module_connected: Option<unsafe extern "C" fn(fd: c_int)>,
}
