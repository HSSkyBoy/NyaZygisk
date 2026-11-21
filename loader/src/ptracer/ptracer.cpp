#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/system_properties.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <type_traits>
#include <vector>

#include "daemon.hpp"
#include "logging.hpp"
#include "main.hpp"
#include "misc.hpp"
#include "utils.hpp"

/**
 * @brief Shared logic to remotely load and initialize the injector library.
 */
static bool execute_remote_injection(int pid, struct user_regs_struct &regs, const char *lib_path,
                                     TraceMode mode) {
#if defined(__aarch64__)
    // Clear the BTYPE field (bits 10 and 11) in PSTATE.
    // Whatever indirect branch the tracee last took may have left BTYPE at 0b11.
    // If we jump into BTI-protected bionic libraries (like libdl.so) with BTYPE=0b11,
    // the CPU will throw a Branch Target Exception (SIGILL). The caller keeps the
    // original PSTATE in its backup, so the tracee still validates its own BTI pad
    // upon final resume.
    regs.pstate &= ~(3ULL << 10);
#endif

    // Reserve red-zone/scratch slack below the interrupted frame before pushing arguments.
    regs.REG_SP = (regs.REG_SP - 256) & ~uintptr_t{0xf};

    auto map = MapInfo::Scan(std::to_string(pid));
    auto local_map = MapInfo::Scan();
    auto libc_return_addr = find_module_return_addr(map, "libc.so");
    if (libc_return_addr == nullptr) {
        libc_return_addr = reinterpret_cast<void *>(0xdead0000);
    }

    // Remotely call dlopen(lib_path, RTLD_NOW)
    LOGV("executing remote call to dlopen(\"%s\")", lib_path);
    auto dlopen_addr = find_func_addr(local_map, map, "libdl.so", "dlopen");
    if (dlopen_addr == nullptr) {
        LOGE("could not find address of dlopen in the target process");
        return false;
    }
    std::vector<long> args;
    auto remote_lib_path = push_string(pid, regs, lib_path);
    if (remote_lib_path == 0) return false;
    args.push_back((long) remote_lib_path);
    args.push_back((long) RTLD_NOW);
    auto remote_handle =
        remote_call(pid, regs, (uintptr_t) dlopen_addr, (uintptr_t) libc_return_addr, args);

    if (remote_handle == 0) {
        LOGE("remote call to dlopen failed, retrieving error message with dlerror");

        auto dlerror_addr = find_func_addr(local_map, map, "libdl.so", "dlerror");
        if (dlerror_addr == nullptr) {
            LOGE("could not find address of dlerror; cannot retrieve error string");
            return false;
        }

        // Remotely call dlerror() (takes no arguments)
        args.clear();
        auto dlerror_str_addr =
            remote_call(pid, regs, (uintptr_t) dlerror_addr, (uintptr_t) libc_return_addr, args);

        if (dlerror_str_addr == 0) {
            LOGE("remote call to dlerror returned null");
            return false;
        }

        auto strlen_addr = find_func_addr(local_map, map, "libc.so", "strlen");
        if (strlen_addr == nullptr) {
            LOGE("could not find address of strlen; cannot measure error string length");
            return false;
        }

        // Remotely call strlen(dlerror_str_addr)
        args.clear();
        args.push_back(dlerror_str_addr);
        auto dlerror_len =
            remote_call(pid, regs, (uintptr_t) strlen_addr, (uintptr_t) libc_return_addr, args);

        if (dlerror_len == 0 || dlerror_len > 4096) {
            LOGE("dlerror string length is invalid (%" PRIuPTR ")", dlerror_len);
            return false;
        }

        // Read the actual error string from the target process memory
        std::string err(dlerror_len, '\0');
        read_proc(pid, (uintptr_t) dlerror_str_addr, err.data(), dlerror_len);

        LOGE("dlopen error: %s", err.c_str());
        return false;
    }

    LOGI("successfully loaded library via remote dlopen, handle: 0x%" PRIxPTR, remote_handle);

    // Remotely call dlsym(handle, "entry")
    LOGV("executing remote call to dlsym to find the 'entry' symbol");
    auto dlsym_addr = find_func_addr(local_map, map, "libdl.so", "dlsym");
    if (dlsym_addr == nullptr) {
        LOGE("could not find address of dlsym in the target process");
        return false;
    }
    args.clear();
    auto remote_entry_str = push_string(pid, regs, "entry");
    if (remote_entry_str == 0) return false;
    args.push_back(remote_handle);
    args.push_back((long) remote_entry_str);
    auto injector_entry =
        remote_call(pid, regs, (uintptr_t) dlsym_addr, (uintptr_t) libc_return_addr, args);

    if (injector_entry == 0) {
        LOGE("dlsym failed to find the 'entry' symbol in the injected library");
        return false;
    }
    LOGI("found injector entry point at address 0x%" PRIxPTR, injector_entry);

    // Find the address range of the injected library to pass to its entry function.
    map = MapInfo::Scan(std::to_string(pid));
    void *start_addr = nullptr;
    size_t block_size = 0;
    // Use the pathname only to identify the library once, then collect its mappings by
    // device and inode. A substring test is not a safe key for the collection pass: a
    // "(deleted)" suffix on a replaced file, or any second mapping whose path merely
    // contains the same basename, would be folded into the range we later unmap.
    // dev+inode names the file itself, and it also excludes anonymous mappings, whose
    // inode is zero.
    dev_t lib_dev = 0;
    ino_t lib_inode = 0;
    for (const auto &info : map) {
        if (info.inode != 0 && info.path.find("libzygisk.so") != std::string::npos) {
            lib_dev = info.dev;
            lib_inode = info.inode;
            break;
        }
    }
    if (lib_inode != 0) {
        uintptr_t min_start = UINTPTR_MAX;
        uintptr_t max_end = 0;
        for (const auto &info : map) {
            if (info.dev != lib_dev || info.inode != lib_inode) continue;
            if (info.start < min_start) min_start = info.start;
            if (info.end > max_end) max_end = info.end;
        }
        if (min_start < max_end) {
            start_addr = reinterpret_cast<void *>(min_start);
            block_size = max_end - min_start;
        }
    }
    LOGV("found injected library mapped from %p with total size %zu [dev %u:%u inode %lu]",
         start_addr, block_size, major(lib_dev), minor(lib_dev), (unsigned long) lib_inode);

    // Remotely call our entry(start_addr, block_size, path) function
    LOGI("calling the injector's entry function to initialize NyaZygisk");
    args.clear();
    args.push_back((uintptr_t) start_addr);
    args.push_back(block_size);
    auto remote_tmp_path = push_string(pid, regs, zygiskd::GetTmpPath().c_str());
    if (remote_tmp_path == 0) return false;
    args.push_back((long) remote_tmp_path);
    args.push_back(mode);
    // entry() returns void, so only `ok` tells a clean return from a crash inside it. A
    // crash there has already damaged the target -- it ran our code on its own stack -- but
    // reporting success would hide that behind an injected process that misbehaves later.
    bool entry_returned = false;
    remote_call(pid, regs, injector_entry, (uintptr_t) libc_return_addr, args, &entry_returned);
    if (!entry_returned) {
        LOGE("the injector's entry function did not return cleanly in process %d", pid);
        return false;
    }

    return true;
}

/**
 * @brief Injects a shared library into a running process at its main entry point.
 *
 * This function orchestrates the core injection logic. It attaches to the target process,
 * intercepts its execution just before the first instruction, and uses this opportunity
 * to load a shared library (`libzygisk.so`) into the process's address space.
 *
 * The strategy is as follows:
 * 1.  **Parse Kernel Argument Block**: Read the process's stack to find the location of program
 *     arguments, environment variables, and the ELF Auxiliary Vector (auxv).
 * 2.  **Find Entry Point**: From the auxv, extract the `AT_ENTRY` value, which is the memory
 *     address of the program's first executable instruction. The dynamic linker has already
 *     run at this stage, making libraries like `libdl.so` available.
 * 3.  **Hijack Execution**: Overwrite the `AT_ENTRY` value in the process's memory with a
 *     deliberately invalid address. When the process is resumed, it will immediately trigger a
 *     segmentation fault (`SIGSEGV`), which we, as the tracer, can catch. This is a reliable
 *     way to pause the process at the perfect moment.
 * 4.  **execute_remote_injection**: Once the process is paused, we restore the original entry
 * point. We then use `ptrace` to execute functions within the target process's context.
 *     - Remotely call `dlopen()` to load our library.
 *     - Remotely call `dlsym()` to find the address of our library's `entry` function.
 *     - Remotely call our `entry` function to initialize NeoZygisk.
 * 5.  **Restore State**: After injection, restore all CPU registers, which allows the original
 *     entry point to be called when the process is fully resumed.
 *
 * @param pid The Process ID of the target (e.g., Zygote).
 * @param lib_path The absolute path to the shared library to be injected.
 * @return True on successful injection, false otherwise.
 */
bool inject_before_start(int pid, const char *lib_path, TraceMode mode) {
    LOGI("starting early library injection for PID: %d, library: %s", pid, lib_path);

    // Backup of the target's registers, to be restored before detaching.
    struct user_regs_struct regs{}, backup{};
    auto map = MapInfo::Scan(std::to_string(pid));
    if (!get_regs(pid, regs)) {
        LOGE("failed to get registers for PID %d, injection aborted", pid);
        return false;
    }

    // --- Step 1 & 2: Parse Kernel Argument Block to Find Entry Point ---
    // The stack pointer (SP) at process startup points to the Kernel Argument Block.
    // We parse this structure to locate argc, argv, envp, and the auxiliary vector (auxv).
    // Ref:
    // https://cs.android.com/android/platform/superproject/main/+/main:bionic/libc/private/KernelArgumentBlock.h
    LOGV("reading kernel argument block from stack pointer: 0x%lx", (unsigned long) regs.REG_SP);
    auto sp = static_cast<uintptr_t>(regs.REG_SP);

    uintptr_t raw_argc = 0;
    if (read_proc(pid, sp, &raw_argc, sizeof(raw_argc)) != static_cast<ssize_t>(sizeof(raw_argc)) ||
        raw_argc > 4096) {
        LOGE("failed to read valid argc from PID %d stack", pid);
        return false;
    }
    int argc = static_cast<int>(raw_argc);

    auto argv = reinterpret_cast<char **>(sp + sizeof(uintptr_t));
    auto envp = argv + argc + 1;

    // Iterate past the environment variables to find the start of the auxiliary vector.
    // The end of envp is marked by a null pointer.
    auto p = envp;
    bool found_env_end = false;
    for (size_t i = 0; i < 4096; ++i) {
        uintptr_t val = 0;
        if (read_proc(pid, (uintptr_t) p, &val, sizeof(val)) != static_cast<ssize_t>(sizeof(val))) {
            LOGE("failed to read envp entry for PID %d", pid);
            return false;
        }
        if (val != 0) {
            p++;
        } else {
            found_env_end = true;
            break;
        }
    }
    if (!found_env_end) {
        LOGE("envp terminator not found within limit for PID %d", pid);
        return false;
    }
    p++;  // Skip the final null pointer to get to auxv.
    auto auxv = reinterpret_cast<ElfW(auxv_t) *>(p);
    LOGV("parsed process startup info: argc=%d, argv=%p, envp=%p, auxv=%p", argc, argv, envp, auxv);

    // Now, scan the auxiliary vector to find AT_ENTRY. This gives us the program's
    // entry address, which is where execution will begin.
    uintptr_t entry_addr = 0;
    uintptr_t addr_of_entry_addr = 0;
    auto v = auxv;
    for (size_t i = 0; i < 4096; ++i) {
        ElfW(auxv_t) buf{};
        if (read_proc(pid, (uintptr_t) v, &buf, sizeof(buf)) != static_cast<ssize_t>(sizeof(buf))) {
            LOGE("failed to read auxv entry for PID %d", pid);
            return false;
        }
        if (buf.a_type == AT_NULL) {
            break;  // End of auxiliary vector.
        }
        if (buf.a_type == AT_ENTRY) {
            entry_addr = (uintptr_t) buf.a_un.a_val;
            addr_of_entry_addr = (uintptr_t) v + offsetof(ElfW(auxv_t), a_un);
            break;
        }
        v++;
    }

    if (entry_addr == 0) {
        LOGE("failed to find AT_ENTRY in auxiliary vector for PID %d, cannot determine entry point",
             pid);
        return false;
    }
    LOGI("found program entry point at 0x%" PRIxPTR, entry_addr);

    // --- Step 3: Intercept Entry Point ---
    // Temporarily replace AT_ENTRY with a sentinel address so the process traps at entry.
    LOGV("setting entry point breakpoint to intercept execution");
    // For arm32 compatibility, we set the last bit to the same as the entry address.
    uintptr_t break_addr = (-0x05ec1cff & ~1) | (entry_addr & 1);
    if (write_proc(pid, addr_of_entry_addr, &break_addr, sizeof(break_addr)) !=
        static_cast<ssize_t>(sizeof(break_addr))) {
        LOGE("failed to write entry breakpoint to PID %d, injection aborted", pid);
        return false;
    }

    struct EntryRestoreGuard {
        int pid;
        uintptr_t addr;
        uintptr_t orig;
        bool active = true;
        ~EntryRestoreGuard() {
            if (active) {
                write_proc(pid, addr, &orig, sizeof(orig));
            }
        }
    } entry_guard{pid, addr_of_entry_addr, entry_addr};

    int status = 0;
    int forward_sig = 0;
    while (true) {
        if (ptrace(PTRACE_CONT, pid, 0, forward_sig) == -1) {
            PLOGE("ptrace(PTRACE_CONT) failed");
            return false;
        }
        forward_sig = 0;

        if (!wait_for_trace(pid, &status, __WALL)) {
            return false;
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            if (sig == SIGSEGV) {
                break;
            } else if (sig == SIGSTOP) {
                continue;
            } else {
                // Forward non-fatal async signals (e.g. SIGCHLD) instead of aborting early.
                LOGV("forwarding pre-entry signal %d to PID %d", sig, pid);
                forward_sig = sig;
                continue;
            }
        }
    }

    // Verify we are truly at the trap
    if (!get_regs(pid, regs)) {
        LOGE("failed to get registers after SIGSEGV for PID %d", pid);
        return false;
    }
    // Sanity check: ensure we stopped at our invalid address.
    if (static_cast<uintptr_t>(regs.REG_IP & ~1) != (break_addr & ~1)) {
        LOGE("process stopped at unexpected address 0x%lx, expected ~0x%" PRIxPTR,
             (unsigned long) regs.REG_IP, break_addr);
        return false;
    }

    LOGI("successfully intercepted process %d at its entry point", pid);

    // --- Step 4: Remote Code Execution ---
    // First, restore the original entry point in memory.
    entry_guard.active = false;
    if (write_proc(pid, addr_of_entry_addr, &entry_addr, sizeof(entry_addr)) !=
        static_cast<ssize_t>(sizeof(entry_addr))) {
        LOGE("FATAL: failed to restore original entry point, process %d will not recover", pid);
        return false;
    }

    // Backup the current registers before we start making remote calls.
    // It is vital we keep the original PSTATE intact in the backup, so
    // the original executable can securely validate its own BTI pad upon final resume.
    memcpy(&backup, &regs, sizeof(regs));

    bool ok = execute_remote_injection(pid, regs, lib_path, mode);

    // --- Step 5: Restore State ---
    // Always restore original registers (even on injection failure) so the process can resume cleanly.
    backup.REG_IP = (long) entry_addr;
    LOGI("restoring registers before resuming normal execution");
    if (!set_regs(pid, backup)) {
        LOGE("failed to restore original registers for PID %d", pid);
        return false;
    }

    return ok;
}

bool inject_after_start(int pid, const char *lib_path, TraceMode mode) {
    LOGI("starting late library injection for PID: %d, library: %s", pid, lib_path);

    struct user_regs_struct regs{}, backup{};
    if (!get_regs(pid, regs)) {
        LOGE("failed to get registers for PID %d, injection aborted", pid);
        return false;
    }

    // Backup current registers (this includes the current Instruction Pointer).
    memcpy(&backup, &regs, sizeof(regs));

    // The process was interrupted and is likely sleeping inside a syscall.
    // If we simply change REG_IP and continue, the kernel's syscall restart logic
    // will kick in and decrement the instruction pointer by 2 (x86) or 4 (ARM),
    // throwing execution into invalid padding bytes (SIGTRAP) before dlopen.
    // We must artificially clear the syscall state from our working registers.
#if defined(__x86_64__)
    regs.orig_rax = -1;
    regs.rax = 0;
#elif defined(__i386__)
    regs.orig_eax = -1;
    regs.eax = 0;
#elif defined(__arm__)
    regs.uregs[17] = -1;  // orig_r0
    regs.uregs[0] = 0;
#elif defined(__aarch64__)
    regs.regs[0] = 0;  // Clear x0 to prevent -ERESTARTSYS match in kernel
#elif defined(__riscv) && __riscv_xlen == 64
    regs.a0 = 0;
#endif

    // Defer async signals while executing remote calls so SIGCHLD or ART RT signals
    // do not interrupt dlopen() while holding bionic's g_dl_mutex.
    struct AsyncSigMaskGuard {
        int pid;
        uint64_t old_mask = 0;
        bool active = false;
        explicit AsyncSigMaskGuard(int p) : pid(p) {
            if (ptrace(PTRACE_GETSIGMASK, pid, sizeof(old_mask), &old_mask) == 0) {
                uint64_t new_mask = ~uint64_t{0};
                constexpr int kSyncSigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE,
                                             SIGTRAP, SIGABRT, SIGSYS};
                for (int sig : kSyncSigs) {
                    if (sig > 0 && sig <= 64) {
                        new_mask &= ~(uint64_t{1} << (sig - 1));
                    }
                }
                if (ptrace(PTRACE_SETSIGMASK, pid, sizeof(new_mask), &new_mask) == 0) {
                    active = true;
                }
            }
        }
        ~AsyncSigMaskGuard() {
            if (active) {
                ptrace(PTRACE_SETSIGMASK, pid, sizeof(old_mask), &old_mask);
            }
        }
    } sig_guard(pid);

    // Execute the shared remote injection logic
    bool success = execute_remote_injection(pid, regs, lib_path, mode);

    // After remote_call() triggers a userspace SIGSEGV at libc_return_addr, the kernel
    // clears in_syscall state. If the tracee was originally paused inside an interruptible
    // syscall (e.g. ppoll/epoll_pwait), backup.REG_RET holds an internal -ERESTART* value
    // (-512..-516). Restoring it directly leaks errno 512..516 to userspace (crashing
    // ZygoteServer Os.poll). Rewrite those internal restart codes to -EINTR (-4).
    long ret_val = static_cast<long>(backup.REG_RET);
    if (ret_val == -512 || ret_val == -513 || ret_val == -514 || ret_val == -516) {
        LOGV("rewriting kernel restart code %ld to -EINTR for PID %d", ret_val, pid);
        backup.REG_RET = static_cast<std::remove_reference_t<decltype(backup.REG_RET)>>(-EINTR);
#if defined(__x86_64__)
        backup.orig_rax = -1;
#elif defined(__i386__)
        backup.orig_eax = -1;
#elif defined(__arm__)
        backup.uregs[17] = -1;
#endif
    }

    // Restore State directly, whether or not the injection worked: the target is running
    // with the registers we modified, and resuming it with those would send it to our fake
    // return address.
    // The instruction pointer (REG_IP) is already correct in the backup.
    LOGI("restoring registers before resuming normal execution");
    if (!set_regs(pid, backup)) {
        LOGE("failed to restore original registers for PID %d", pid);
        return false;
    }

    return success;
}

// Macro helper to check for specific ptrace stop events.
#define STOPPED_WITH(sig, event)                                                                   \
    (WIFSTOPPED(status) && WSTOPSIG(status) == (sig) && (status >> 16) == (event))

// Common wait routine to avoid repetition.
// Returns false if wait failed or process died unexpectedly.
static bool wait_for_process(int pid, int *status) {
    while (waitpid(pid, status, __WALL) < 0) {
        if (errno == EINTR) continue;
        PLOGE("waitpid on PID %d", pid);
        return false;
    }
    return true;
}

/**
 * @brief Copies the library to a world-readable temporary file to bypass DAC restrictions.
 *
 * Kept for debugging: when the work directory is somewhere the target cannot read, point
 * perform_injection() at this instead of the packaged library to find out whether a failed
 * injection is a permission problem or something else. It is deliberately not wired into
 * the normal path -- it only relocates the library, while the control socket stays where it
 * is, so it cannot on its own make an unreachable work directory usable.
 *
 * @param src_path The original path (e.g., /data/system/nyazygisk/lib64/libzygisk.so)
 * @return The path to the temporary file, or an empty string on failure.
 */
[[maybe_unused]] static std::string copy_to_temp(const std::string &src_path) {
    char tmp_path[] = "/data/local/tmp/zygisk_XXXXXX.so";

    // mkstemps securely creates the file with a random 6-character string replacing XXXXXX.
    // The '3' tells it to preserve the ".so" suffix.
    int fd_out = mkstemps(tmp_path, 3);
    if (fd_out < 0) {
        PLOGE("failed to create temporary file in /data/local/tmp");
        return "";
    }

    int fd_in = open(src_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_in < 0) {
        PLOGE("failed to open source library: %s", src_path.c_str());
        close(fd_out);
        unlink(tmp_path);
        return "";
    }

    // Copy contents
    char buf[4096];
    ssize_t bytes_read;
    while ((bytes_read = read(fd_in, buf, sizeof(buf))) > 0) {
        if (write(fd_out, buf, bytes_read) != bytes_read) {
            PLOGE("failed to write to temporary library");
            close(fd_in);
            close(fd_out);
            unlink(tmp_path);
            return "";
        }
    }

    close(fd_in);
    close(fd_out);

    // Make the file world-readable (and executable) so UID 1000 (system_server) can load it.
    if (chmod(tmp_path, 0755) != 0) {
        PLOGE("failed to chmod temporary library %s", tmp_path);
    }

    LOGV("created temporary library copy at: %s", tmp_path);
    return std::string(tmp_path);
}

/**
 * @brief Injects the Zygisk library into the main thread.
 *
 * Shared logic between Seize and Attach methods.
 */
static bool perform_injection(int pid, TraceMode mode) {
    std::string lib_path = zygiskd::GetTmpPath();
    lib_path += "/lib" LP_SELECT("", "64") "/libzygisk.so";
    bool process_started = mode == TraceMode::STANDALONE || mode == TraceMode::SYSTEM_SERVER;

    if (process_started) {
        return inject_after_start(pid, lib_path.c_str(), mode);
    }
    return inject_before_start(pid, lib_path.c_str(), mode);
}

// The injector scrubs task->ptrace_message with a seccomp event, which the kernel raises only
// for a tracer that asked for it: without this flag it answers -ENOSYS and skips the event.
// Kept out of the attach itself, since a kernel that refuses the flag would refuse the attach
// with it, and losing the scrub beats losing the injection.
static void arm_seccomp_events(int pid, int options) {
    if (!kernel_keeps_ptrace_message()) return;
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, options | PTRACE_O_TRACESECCOMP) == -1) {
        PLOGE("set PTRACE_O_TRACESECCOMP on pid %d", pid);
    }
}

/**
 * @brief Executes the GKI 2.0 Workaround and detaches.
 *
 * Advances the process by one syscall to clear internal kernel ptrace state
 * before finally detaching.
 */
static bool detach_with_gki_workaround(int pid, int detach_signal) {
    int status;
    LOGV("applying GKI 2.0 workaround (step syscall) before detach");

    // 1. Advance to next syscall entry/exit to clear signal-stop state
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
        PLOGE("ptrace(PTRACE_SYSCALL) on PID %d", pid);
        ptrace(PTRACE_DETACH, pid, 0, detach_signal);  // Try to detach anyway
        return false;
    }

    // 2. Wait for the syscall stop
    if (!wait_for_process(pid, &status)) {
        // If wait fails, force detach
        ptrace(PTRACE_DETACH, pid, 0, detach_signal);
        return false;
    }

    // 3. Clean detach
    if (ptrace(PTRACE_DETACH, pid, 0, detach_signal) == -1) {
        PLOGE("ptrace(PTRACE_DETACH) on PID %d", pid);
        return false;
    }
    return true;
}

// --- Strategy 1: PTRACE_SEIZE (Preferred) ---

static bool trace_with_seize(int pid, TraceMode mode, int *seize_errno) {
    LOGI("attempting trace_seize on PID %d", pid);
    if (seize_errno) *seize_errno = 0;

    bool process_started = mode == TraceMode::STANDALONE || mode == TraceMode::SYSTEM_SERVER;

    int options = process_started ? 0 : PTRACE_O_EXITKILL;
    // PTRACE_O_EXITKILL ensures target dies if we crash, preventing a zombie state.
    if (ptrace(PTRACE_SEIZE, pid, 0, options) == -1) {
        if (seize_errno) *seize_errno = errno;
        return false;
    }

    if (process_started) {
        // PTRACE_SEIZE does NOT stop the process. We must explicitly interrupt it.
        LOGV("late mode: sending PTRACE_INTERRUPT to pause the running process");
        if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == -1) {
            PLOGE("ptrace(PTRACE_INTERRUPT) on PID %d", pid);
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return false;
        }
    }

    int status;
// Helper macro for local flow control
#define BAIL_AND_DETACH                                                                            \
    ptrace(PTRACE_DETACH, pid, 0, 0);                                                              \
    return false;

    // Wait for the initial Seize stop
    if (!wait_for_process(pid, &status)) {
        BAIL_AND_DETACH
    }

    // Determine the expected stop signal.
    // Spawn flow (already SIGSTOPped): SIGSTOP, with PTRACE_EVENT_STOP or plain event 0
    // if the target was already in a stopped state from the monitor hand-off.
    // Late flow (PTRACE_INTERRUPT):    SIGTRAP + PTRACE_EVENT_STOP
    bool valid_stop = process_started
                          ? STOPPED_WITH(SIGTRAP, PTRACE_EVENT_STOP)
                          : (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP &&
                             ((status >> 16) == PTRACE_EVENT_STOP || (status >> 16) == 0));

    if (valid_stop) {
        arm_seccomp_events(pid, options);

        // 1. Inject Payload
        if (!perform_injection(pid, mode)) {
            BAIL_AND_DETACH
        }

        if (process_started) {
            // We interrupted a thread of a live process instead of finding it parked in
            // SIGSTOP, so it needs no SIGCONT to wake up -- only a detach, which resumes it
            // exactly where it was. Detach here rather than leaving it to this process
            // exiting: the kernel would release the tracee either way, but only at a point
            // we no longer control, and a tracer that goes on to do anything else would
            // hold a live zygote or system_server stopped while it did.
            LOGV("late injection complete, detaching from PID %d", pid);
            if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
                // The injection itself succeeded, and the tracee is released anyway once
                // this process exits, so this is worth reporting but not failing over.
                PLOGE("ptrace(PTRACE_DETACH) on PID %d", pid);
            }
            return true;
        } else {
            LOGV("injection complete, starting signal continuation sequence");

            // 2. Send SIGCONT to the process
            if (kill(pid, SIGCONT) == -1) {
                PLOGE("kill(SIGCONT) on PID %d", pid);
                BAIL_AND_DETACH
            }

            // 3. Resume (PTRACE_CONT)
            if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
                PLOGE("ptrace(PTRACE_CONT) failed");
                BAIL_AND_DETACH
            }
            if (!wait_for_process(pid, &status)) {
                BAIL_AND_DETACH
            }

            // 4. Expect SIGTRAP (caused by the signal interruption in Seize mode)
            if (STOPPED_WITH(SIGTRAP, PTRACE_EVENT_STOP)) {
                if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
                    BAIL_AND_DETACH
                }
                if (!wait_for_process(pid, &status)) {
                    BAIL_AND_DETACH
                }

                // 5. Expect the actual SIGCONT delivery
                if (STOPPED_WITH(SIGCONT, 0)) {
                    LOGV("received expected SIGCONT");
                    // 6. Workaround + Detach
                    return detach_with_gki_workaround(pid, SIGCONT);
                } else {
                    LOGE("unexpected state after SIGTRAP: %s", parse_status(status).c_str());
                    BAIL_AND_DETACH
                }
            } else if (STOPPED_WITH(SIGCONT, 0)) {
                // Direct SIGCONT delivery without intermediate SIGTRAP
                LOGV("received direct SIGCONT");
                return detach_with_gki_workaround(pid, SIGCONT);
            } else {
                LOGE("expected SIGTRAP/SIGCONT after CONT, got: %s", parse_status(status).c_str());
                BAIL_AND_DETACH
            }
        }
    } else {
        LOGE("seize attached, but unexpected initial state: %s", parse_status(status).c_str());
        BAIL_AND_DETACH
    }

#undef BAIL_AND_DETACH
    return true;
}

// --- Strategy 2: PTRACE_ATTACH (Fallback) ---

static bool trace_with_attach(int pid, TraceMode mode) {
    LOGI("falling back to trace_attach on PID %d", pid);

    // Classic attach. This sends SIGSTOP to the process immediately.
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        PLOGE("ptrace(PTRACE_ATTACH) on PID %d", pid);
        return false;
    }

    int status;
    if (!wait_for_process(pid, &status)) {
        // If wait fails, we must try to detach or the process hangs forever
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }

    // Classic ATTACH results in a STOPPED status with SIGSTOP.
    // It does NOT use PTRACE_EVENT_STOP in the status bits usually.
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
        int options = mode == TraceMode::SPAWN ? PTRACE_O_EXITKILL : 0;
        if (options != 0) {
            // Set EXITKILL for parity with SEIZE
            ptrace(PTRACE_SETOPTIONS, pid, 0, options);
        }
        arm_seccomp_events(pid, options);

        // 1. Inject Payload
        if (!perform_injection(pid, mode)) {
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return false;
        }

        // 2. Detach
        // For classic attach, we don't need the SIGTRAP/SIGCONT dance because
        // we haven't manually sent a SIGCONT via kill().
        // The process is simply stopped by the attach.
        // We use the GKI workaround to ensure the detach is clean.
        // We pass SIGCONT to detach to ensure the process resumes.
        return detach_with_gki_workaround(pid, SIGCONT);

    } else {
        LOGE("attach succeeded but process state unexpected: %s", parse_status(status).c_str());
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }
}

/**
 * @brief Attaches to the target process and initiates the injection.
 *
 * Tries modern PTRACE_SEIZE first. If that fails with I/O error (EIO),
 * falls back to classic PTRACE_ATTACH.
 *
 * @return True on success, false on failure.
 */
bool trace_target(int pid, TraceMode mode) {
    LOGI("attaching to process [PID: %d, mode : %d]", pid, mode);

    // 1. Try SEIZE (Modern, robust handling of group stops)
    int seize_errno = 0;
    if (trace_with_seize(pid, mode, &seize_errno)) {
        LOGI("successfully detached from %d (via SEIZE), NyaZygisk active", pid);
        return true;
    }

    // 2. Check for fallback condition
    // PTRACE_SEIZE returns EIO if the process state prohibits seizing,
    // or sometimes if security modules interfere.
    if (seize_errno == EIO) {
        LOGW("PTRACE_SEIZE failed with EIO, attempting fallback to PTRACE_ATTACH");

        if (trace_with_attach(pid, mode)) {
            LOGI("successfully detached from %d (via ATTACH), NyaZygisk active", pid);
            return true;
        }
    } else if (seize_errno != 0) {
        // If it wasn't EIO (e.g., EPERM, ESRCH), Attach will likely fail too,
        // or the error is fatal.
        errno = seize_errno;
        PLOGE("PTRACE_SEIZE failed (errno: %d)", seize_errno);
    }

    return false;
}
