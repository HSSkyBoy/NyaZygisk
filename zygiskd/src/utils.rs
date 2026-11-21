// src/utils.rs

//! A collection of utility functions for platform-specific operations.
//!
//! This module provides helpers for:
//! - Interacting with Android properties and SELinux contexts.
//! - Low-level Unix socket and pipe I/O.
//! - A trait (`UnixStreamExt`) for simplified socket communication.

use anyhow::Result;
use rustix::net::{
    AddressFamily, SendFlags, SocketAddrUnix, SocketType, bind, connect, listen, sendto, socket,
};
use rustix::thread as rustix_thread;
use std::ffi::{CString, c_char};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Command;
use std::{
    fs,
    io::{Read, Write},
};

// --- Platform-specific Macros ---

/// Selects an expression based on the target pointer width (32-bit vs 64-bit).
#[cfg(target_pointer_width = "64")]
#[macro_export]
macro_rules! lp_select {
    ($lp32:expr, $lp64:expr) => {
        $lp64
    };
}
#[cfg(target_pointer_width = "32")]
#[macro_export]
macro_rules! lp_select {
    ($lp32:expr, $lp64:expr) => {
        $lp32
    };
}

/// Selects an expression based on the build profile (debug vs release).
#[cfg(debug_assertions)]
#[macro_export]
macro_rules! debug_select {
    ($debug:expr, $release:expr) => {
        $debug
    };
}
#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! debug_select {
    ($debug:expr, $release:expr) => {
        $release
    };
}

// --- SELinux and Android Property Utilities ---

/// Sets the SELinux context for socket creation for the current thread.
pub fn set_socket_create_context(context: &str) -> Result<()> {
    // Try the modern path first.
    let path = "/proc/thread-self/attr/sockcreate";
    if fs::write(path, context).is_ok() {
        return Ok(());
    }
    // Fallback for older kernels.
    let fallback_path = format!(
        "/proc/self/task/{}/attr/sockcreate",
        rustix_thread::gettid().as_raw_nonzero()
    );
    fs::write(fallback_path, context)?;
    Ok(())
}

/// Gets the current SELinux context of the process.
pub fn get_current_attr() -> Result<String> {
    let s = fs::read_to_string("/proc/self/attr/current")?;
    Ok(s.trim().to_string())
}

/// Retrieves an Android system property value.
pub fn get_property(name: &str) -> Result<String> {
    let name = CString::new(name)?;
    let mut buf = vec![0u8; 92]; // PROP_VALUE_MAX
    let len = unsafe { __system_property_get(name.as_ptr(), buf.as_mut_ptr() as *mut c_char) };
    if len > 0 {
        let len = (len as usize).min(buf.len() - 1);
        Ok(String::from_utf8_lossy(&buf[..len]).to_string())
    } else {
        Ok(String::new())
    }
}

// --- Unix Socket and IPC Extensions ---

/// Maximum string length accepted over the daemon IPC socket (64 KiB).
const MAX_IPC_STRING_LEN: usize = 64 * 1024;

/// An extension trait for `UnixStream` to simplify reading and writing common data types.
pub trait UnixStreamExt {
    fn read_u8(&mut self) -> Result<u8>;
    fn read_u32(&mut self) -> Result<u32>;
    fn read_usize(&mut self) -> Result<usize>;
    fn read_string(&mut self) -> Result<String>;
    fn write_u8(&mut self, value: u8) -> Result<()>;
    fn write_u32(&mut self, value: u32) -> Result<()>;
    fn write_usize(&mut self, value: usize) -> Result<()>;
    fn write_string(&mut self, value: &str) -> Result<()>;
}

impl UnixStreamExt for UnixStream {
    fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_ne_bytes(buf))
    }

    fn read_usize(&mut self) -> Result<usize> {
        let mut buf = [0u8; std::mem::size_of::<usize>()];
        self.read_exact(&mut buf)?;
        Ok(usize::from_ne_bytes(buf))
    }

    fn read_string(&mut self) -> Result<String> {
        let len = self.read_usize()?;
        if len > MAX_IPC_STRING_LEN {
            anyhow::bail!("IPC string length {} exceeds limit {}", len, MAX_IPC_STRING_LEN);
        }
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf)?;
        Ok(String::from_utf8(buf)?)
    }

    fn write_u8(&mut self, value: u8) -> Result<()> {
        self.write_all(&[value])?;
        Ok(())
    }

    fn write_u32(&mut self, value: u32) -> Result<()> {
        self.write_all(&value.to_ne_bytes())?;
        Ok(())
    }

    fn write_usize(&mut self, value: usize) -> Result<()> {
        self.write_all(&value.to_ne_bytes())?;
        Ok(())
    }

    fn write_string(&mut self, value: &str) -> Result<()> {
        self.write_usize(value.len())?;
        self.write_all(value.as_bytes())?;
        Ok(())
    }
}

/// Returns the kernel-verified peer credentials (`SO_PEERCRED`) of a connected Unix socket.
pub fn peer_cred(stream: &UnixStream) -> Option<libc::ucred> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (ret == 0).then_some(cred)
}

/// Returns the real uid of the process on the other end of a connected Unix domain
/// socket, as reported by the kernel (`SO_PEERCRED`), or `None` if it could not be
/// determined. Unlike any uid a client sends as part of its request payload, this
/// cannot be spoofed by the client.
pub fn peer_uid(stream: &UnixStream) -> Option<u32> {
    peer_cred(stream).map(|cred| cred.uid)
}

/// Creates a `UnixListener` bound to a given path, handling file cleanup and SELinux contexts.
pub fn unix_listener_from_path(path: &str) -> Result<UnixListener> {
    let _ = fs::remove_file(path);
    let addr = SocketAddrUnix::new(path)?;
    let socket = socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
    bind(&socket, &addr)?;
    listen(&socket, 128)?;
    // Label the socket with the AOSP built-in zygote_socket type so zygote and
    // system_server may connect on enforcing-SELinux devices without declaring a custom type.
    match Command::new("chcon")
        .arg("u:object_r:zygote_socket:s0")
        .arg(path)
        .status()
    {
        Ok(status) if !status.success() => {
            log::warn!("chcon on {} exited with {}", path, status);
        }
        Err(e) => {
            log::warn!("failed to run chcon on {}: {}", path, e);
        }
        Ok(_) => {}
    }
    // Open by DAC, so a late-injected system_server can reach the socket as uid 1000.
    // This is not the gate: access is controlled by the `0550 system:system` parent
    // directory, the `zygote_socket` label above on an enforcing device, and the
    // per-action SO_PEERCRED checks in `handle_connection`.
    let chmod_status = Command::new("chmod").arg("777").arg(path).status()?;
    if !chmod_status.success() {
        log::warn!("chmod 777 on {} exited with {}", path, chmod_status);
    }
    Ok(UnixListener::from(socket))
}

/// Sends a datagram packet to a Unix socket path.
pub fn unix_datagram_sendto(path: &str, buf: &[u8]) -> Result<()> {
    let _ = set_socket_create_context(&get_current_attr().unwrap_or_default());
    let addr = SocketAddrUnix::new(path.as_bytes())?;
    let socket = socket(AddressFamily::UNIX, SocketType::DGRAM, None)?;
    connect(&socket, &addr)?;
    let res = sendto(socket, buf, SendFlags::empty(), &addr);
    let _ = set_socket_create_context("");
    res?;
    Ok(())
}

/// Checks if a Unix socket is still alive and connected using `poll`.
pub fn is_socket_alive(stream: &UnixStream) -> bool {
    let pfd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let mut pfds = [pfd];
    loop {
        // A timeout of 0 makes poll return immediately.
        let ret = unsafe { libc::poll(pfds.as_mut_ptr(), 1, 0) };
        if ret < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return false;
        }
        // If `revents` has any flag other than POLLIN (e.g., POLLHUP, POLLERR), the socket is dead.
        return pfds[0].revents & !libc::POLLIN == 0;
    }
}

/// Receives a single file descriptor accompanied by a 1-byte payload via `SCM_RIGHTS`,
/// setting `FD_CLOEXEC` atomically. Works on both `SOCK_STREAM` and `SOCK_DGRAM` Unix sockets.
pub fn recv_fd_cloexec(sockfd: RawFd) -> std::io::Result<OwnedFd> {
    let mut dummy: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };
    #[repr(C)]
    union ControlBuf {
        _align: libc::cmsghdr,
        buf: [u8; 64],
    }
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize };
    assert!(cmsg_space <= 64);
    let mut control = ControlBuf { buf: [0u8; 64] };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = unsafe { control.buf.as_mut_ptr() as *mut libc::c_void };
    msg.msg_controllen = cmsg_space as _;

    let n = loop {
        let ret = unsafe { libc::recvmsg(sockfd, &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        break ret;
    };

    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "peer closed socket while receiving fd",
        ));
    }

    let mut received: Option<OwnedFd> = None;
    let mut overflow = false;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let hdr_len = libc::CMSG_LEN(0) as usize;
                let total_len = (*cmsg).cmsg_len as usize;
                if total_len >= hdr_len {
                    let nfds = (total_len - hdr_len) / std::mem::size_of::<RawFd>();
                    let data = libc::CMSG_DATA(cmsg);
                    for i in 0..nfds {
                        let mut fd: RawFd = -1;
                        std::ptr::copy_nonoverlapping(
                            data.add(i * std::mem::size_of::<RawFd>()),
                            &mut fd as *mut RawFd as *mut u8,
                            std::mem::size_of::<RawFd>(),
                        );
                        if fd >= 0 {
                            if received.is_none() {
                                received = Some(OwnedFd::from_raw_fd(fd));
                            } else {
                                overflow = true;
                                libc::close(fd);
                            }
                        }
                    }
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    if (msg.msg_flags & libc::MSG_CTRUNC) != 0 || overflow {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "control message truncated or contained extra fds",
        ));
    }

    received.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no SCM_RIGHTS file descriptor attached",
        )
    })
}

// --- FFI for Android System APIs ---
unsafe extern "C" {
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> libc::c_int;
    // Other __system_property functions could be declared here if needed.
}
