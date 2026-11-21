// src/mount.rs

//! Manages Linux mount namespaces for the NeoZygisk daemon.
//!
//! This module provides a unified API for caching, cleaning, and switching
//! between different mount namespaces, which is crucial for isolating Zygisk
//! modules and providing them with a clean environment.

use anyhow::{Result, bail};
use log::{debug, trace};
use procfs::process::{MountInfo, Process};
use rustix::thread as rustix_thread;
use std::ffi::CString;
use std::fs;
use std::io::Error;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::{Arc, RwLock};

use crate::root_impl;

/// Represents the two types of mount namespaces the daemon manages.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum MountNamespace {
    /// A "clean" namespace with all root-related mounts removed.
    Clean,
    /// The root namespace of the system, as seen by Zygote.
    Root,
}

impl TryFrom<u8> for MountNamespace {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MountNamespace::Clean),
            1 => Ok(MountNamespace::Root),
            _ => anyhow::bail!("Invalid MountNamespace value: {}", value),
        }
    }
}

/// Switches the current thread into the mount namespace of a given process.
pub fn switch_mount_namespace(pid: i32) -> Result<()> {
    // Entering the namespace is the point of this call. Saving and restoring the working
    // directory around it is a convenience and must not be able to fail it: a module
    // update can have renamed the tree this process was started from.
    let cwd = std::env::current_dir();
    let mnt_ns_file = fs::File::open(format!("/proc/{}/ns/mnt", pid))?;
    rustix_thread::move_into_link_name_space(
        mnt_ns_file.as_fd(),
        Some(rustix_thread::LinkNameSpaceType::Mount),
    )?;
    // `setns` can change the current working directory, so we restore it.
    match cwd {
        Ok(cwd) => {
            if let Err(e) = std::env::set_current_dir(&cwd) {
                debug!("Could not restore the working directory {:?}: {}", cwd, e);
            }
        }
        Err(e) => debug!("Could not read the working directory to restore it: {}", e),
    }
    Ok(())
}

/// RAII guard ensuring a helper child is always killed and reaped on every exit path.
struct ChildReapGuard(libc::pid_t);

impl Drop for ChildReapGuard {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.0, libc::SIGKILL);
            while libc::waitpid(self.0, std::ptr::null_mut(), 0) == -1 {
                if Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    break;
                }
            }
        }
    }
}

/// Manages the lifecycle and caching of mount namespace file descriptors.
///
/// This manager is responsible for creating and holding onto file descriptors
/// that represent specific mount namespaces, preventing them from being destroyed.
pub struct MountNamespaceManager {
    clean_mnt_ns_fd: RwLock<Option<Arc<OwnedFd>>>,
    root_mnt_ns_fd: RwLock<Option<Arc<OwnedFd>>>,
}

impl MountNamespaceManager {
    /// Creates a new, empty `MountNamespaceManager`.
    pub fn new() -> Self {
        Self {
            clean_mnt_ns_fd: RwLock::new(None),
            root_mnt_ns_fd: RwLock::new(None),
        }
    }

    fn get_namespace_storage(
        &self,
        namespace_type: MountNamespace,
    ) -> &RwLock<Option<Arc<OwnedFd>>> {
        match namespace_type {
            MountNamespace::Clean => &self.clean_mnt_ns_fd,
            MountNamespace::Root => &self.root_mnt_ns_fd,
        }
    }

    /// Gets the cached file descriptor for a given namespace type, if it exists.
    /// Returns a cloned `Arc<OwnedFd>` so concurrent `reset()` cannot close the FD
    /// while a caller is sending it over a Unix socket.
    pub fn get_namespace_fd(&self, namespace_type: MountNamespace) -> Option<Arc<OwnedFd>> {
        let storage = self.get_namespace_storage(namespace_type);
        let guard = storage.read().ok()?;
        guard.as_ref().map(Arc::clone)
    }

    /// Resets cached namespace file descriptors (e.g. on soft reboot / Zygote restart).
    pub fn reset(&self) {
        if let Ok(mut guard) = self.clean_mnt_ns_fd.write() {
            *guard = None;
        }
        if let Ok(mut guard) = self.root_mnt_ns_fd.write() {
            *guard = None;
        }
        debug!("MountNamespaceManager: reset cached mount namespaces");
    }

    /// Collects the ordered list of mount points to detach for a clean namespace.
    /// Runs in the parent BEFORE `fork()` so the child never allocates or logs after fork.
    fn collect_unmount_targets(pid: i32) -> Result<Vec<CString>> {
        let mount_infos = Process::new(pid)?.mountinfo()?;
        let mut unmount_targets: Vec<MountInfo> = Vec::new();

        let root_sources: &[&str] = &["magisk", "KSU", "APatch", "kpatch"];

        let ksu_module_source: Option<String> =
            if matches!(root_impl::get(), root_impl::RootImpl::KernelSU) {
                mount_infos
                    .iter()
                    .find(|info| info.mount_point.as_path().to_str() == Some("/data/adb/modules"))
                    .and_then(|info| info.mount_source.clone())
                    .filter(|source| source.starts_with("/dev/block/loop"))
            } else {
                None
            };

        for info in mount_infos {
            let path_str = info.mount_point.to_str().unwrap_or("");
            let mount_source_str = info.mount_source.as_deref();

            let should_unmount = info.root.starts_with("/adb/modules")
                || path_str.starts_with("/data/adb/modules")
                || mount_source_str.map_or(false, |source| root_sources.contains(&source))
                || (ksu_module_source.is_some() && info.mount_source == ksu_module_source);

            if should_unmount {
                unmount_targets.push(info);
            }
        }

        // Unmount in reverse order of mnt_id to handle nested mounts correctly.
        unmount_targets.sort_by_key(|a| std::cmp::Reverse(a.mnt_id));

        let mut cpaths = Vec::with_capacity(unmount_targets.len());
        for target in unmount_targets {
            if let Some(path) = target.mount_point.to_str() {
                debug!("Queued unmount {} (mnt_id: {})", path, target.mnt_id);
                if let Ok(cstr) = CString::new(path) {
                    cpaths.push(cstr);
                }
            }
        }
        Ok(cpaths)
    }

    /// Caches a handle to a specific mount namespace (`Clean` or `Root`).
    ///
    /// # Arguments
    /// * `pid` - The PID of a process currently in the target mount namespace.
    /// * `namespace_type` - The type of namespace to save.
    pub fn save_mount_namespace(
        &self,
        pid: i32,
        namespace_type: MountNamespace,
    ) -> Result<Arc<OwnedFd>> {
        let storage = self.get_namespace_storage(namespace_type);
        {
            let guard = storage
                .read()
                .map_err(|e| anyhow::anyhow!("poisoned lock: {}", e))?;
            if let Some(fd) = guard.as_ref() {
                return Ok(Arc::clone(fd));
            }
        }

        // Prepare every heap allocation BEFORE fork() so the child in a multi-threaded
        // daemon calls only async-signal-safe libc syscalls and never deadlocks on
        // allocator or logger mutexes.
        let pid_ns_path = CString::new(format!("/proc/{}/ns/mnt", pid))?;
        let unmount_targets = if namespace_type == MountNamespace::Clean {
            Self::collect_unmount_targets(pid)?
        } else {
            Vec::new()
        };

        // Create a pipe for synchronization between parent and child.
        let (pipe_reader, pipe_writer) = rustix::pipe::pipe()?;
        let reader_fd = pipe_reader.as_raw_fd();
        let writer_fd = pipe_writer.as_raw_fd();

        match unsafe { libc::fork() } {
            0 => {
                // --- Child Process (async-signal-safe syscalls only) ---
                unsafe {
                    libc::close(reader_fd);

                    let ns_fd =
                        libc::open(pid_ns_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                    if ns_fd < 0 {
                        libc::_exit(1);
                    }
                    if libc::setns(ns_fd, libc::CLONE_NEWNS) != 0 {
                        libc::close(ns_fd);
                        libc::_exit(2);
                    }
                    libc::close(ns_fd);

                    if namespace_type == MountNamespace::Clean {
                        if libc::unshare(libc::CLONE_NEWNS) != 0 {
                            libc::_exit(3);
                        }
                        for target in &unmount_targets {
                            let _ = libc::umount2(target.as_ptr(), libc::MNT_DETACH);
                        }
                    }

                    // Signal to the parent that setup is complete.
                    let sig: u8 = 0;
                    let _ = libc::write(
                        writer_fd,
                        &sig as *const u8 as *const libc::c_void,
                        1,
                    );
                    libc::close(writer_fd);

                    // Wait indefinitely until parent kills us after opening /proc/<child>/ns/mnt.
                    loop {
                        libc::pause();
                    }
                }
            }
            child_pid if child_pid > 0 => {
                // --- Parent Process ---
                let _reap_guard = ChildReapGuard(child_pid);
                drop(pipe_writer);

                // Guard against a hung child with a bounded poll timeout.
                let mut pfd = libc::pollfd {
                    fd: pipe_reader.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                loop {
                    let pret = unsafe { libc::poll(&mut pfd, 1, 5000) };
                    if pret < 0 {
                        if Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                            continue;
                        }
                        bail!("poll on mount-ns helper pipe failed: {}", Error::last_os_error());
                    }
                    if pret == 0 {
                        bail!("mount-ns helper child {} timed out", child_pid);
                    }
                    break;
                }

                let mut buf: [u8; 1] = [0];
                if rustix::io::read(&pipe_reader, &mut buf)? == 0 {
                    bail!(
                        "child {} exited before setting up the mount namespace",
                        child_pid
                    );
                }
                trace!("Child {} finished setting up mount namespace.", child_pid);

                let ns_path = format!("/proc/{}/ns/mnt", child_pid);
                let ns_file = fs::File::open(&ns_path)?;
                let ns_arc = Arc::new(OwnedFd::from(ns_file));

                let raw_fd = ns_arc.as_raw_fd();
                let mut guard = storage
                    .write()
                    .map_err(|e| anyhow::anyhow!("poisoned lock: {}", e))?;
                *guard = Some(Arc::clone(&ns_arc));

                trace!("{:?} namespace cached as FD {}", namespace_type, raw_fd);
                Ok(ns_arc)
            }
            _ => bail!(Error::last_os_error()),
        }
    }
}

impl Default for MountNamespaceManager {
    fn default() -> Self {
        Self::new()
    }
}
