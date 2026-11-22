#include "stage.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "daemon.hpp"
#include "logging.hpp"
#include "main.hpp"
#include "utils.hpp"

using namespace std::string_view_literals;

namespace {

constexpr uid_t kAidRoot = 0;
constexpr gid_t kGidRoot = 0;
constexpr uid_t kAidSystem = 1000;
constexpr gid_t kGidSystem = 1000;
constexpr const char *kSystemFileContext = "u:object_r:system_file:s0";

bool is_dir(const std::string &path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool is_regular_file(const std::string &path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

bool path_exists(const std::string &path) { return access(path.c_str(), F_OK) == 0; }

bool caller_fans_out() {
    const char *ksu = getenv("KSU");
    const char *apatch = getenv("APATCH");
    return (ksu != nullptr && ksu[0] != '\0') || (apatch != nullptr && apatch[0] != '\0');
}

bool on_path(std::string_view binary) {
    const char *path_env = getenv("PATH");
    std::string_view paths =
        (path_env != nullptr && path_env[0] != '\0') ? path_env : "/system/bin:/vendor/bin";

    while (!paths.empty()) {
        auto sep = paths.find(':');
        auto dir = paths.substr(0, sep);
        if (!dir.empty()) {
            std::string candidate;
            candidate.reserve(dir.size() + 1 + binary.size());
            candidate.append(dir);
            if (candidate.back() != '/') candidate.push_back('/');
            candidate.append(binary);
            if (access(candidate.c_str(), X_OK) == 0) {
                return true;
            }
        }
        if (sep == std::string_view::npos) break;
        paths.remove_prefix(sep + 1);
    }
    return false;
}

// Stand down only for Magisk's built-in Zygisk. NyaZygisk sets ZYGISK_ENABLED=1 inside
// the manager app, and su / ksud soft-reboot inherit the manager's environment.
bool should_stand_down() {
    const char *zygisk_enabled = getenv("ZYGISK_ENABLED");
    return zygisk_enabled != nullptr && zygisk_enabled[0] != '\0' && !caller_fans_out() &&
           on_path("magisk");
}

void set_selinux_context(const std::string &path, const char *ctx) {
    if (lsetxattr(path.c_str(), "security.selinux", ctx, strlen(ctx) + 1, 0) == -1 &&
        errno != ENOTSUP && errno != EOPNOTSUPP) {
        LOGW("stage: lsetxattr %s -> %s failed: %s (%d)", path.c_str(), ctx, strerror(errno),
             errno);
    }
}

bool mkdir_p(const std::string &path, mode_t mode) {
    if (path.empty()) return false;
    if (is_dir(path)) return true;

    std::string cur;
    cur.reserve(path.size());
    size_t pos = 0;
    if (path[0] == '/') {
        cur.push_back('/');
        pos = 1;
    }

    while (pos <= path.size()) {
        auto slash = path.find('/', pos);
        auto part = (slash == std::string::npos) ? path.substr(pos) : path.substr(pos, slash - pos);
        if (!part.empty()) {
            if (!cur.empty() && cur.back() != '/') cur.push_back('/');
            cur.append(part);
            if (mkdir(cur.c_str(), mode) == -1 && errno != EEXIST) {
                PLOGE("stage: mkdir %s", cur.c_str());
                return false;
            }
        }
        if (slash == std::string::npos) break;
        pos = slash + 1;
    }
    return is_dir(path);
}

// The work directory has to be traversable by uid 1000: a late-injected system_server
// dlopens the library and connects to the control socket in its own context, and that is a
// DAC check which no SELinux setting relaxes. Hence system:system ownership and 0550 so only
// root (via CAP_DAC_OVERRIDE) and system may traverse or list it.
bool create_sys_perm(const std::string &dir) {
    if (!mkdir_p(dir, 0550)) return false;
    if (chmod(dir.c_str(), 0550) == -1) {
        LOGW("stage: chmod 0550 %s failed: %s (%d)", dir.c_str(), strerror(errno), errno);
    }
    set_selinux_context(dir, kSystemFileContext);
    if (chown(dir.c_str(), kAidSystem, kGidSystem) == -1) {
        LOGW("stage: chown system:system %s failed: %s (%d)", dir.c_str(), strerror(errno), errno);
    }
    return true;
}

bool copy_file(const std::string &src, const std::string &dst, mode_t mode) {
    int in_fd = open(src.c_str(), O_RDONLY | O_CLOEXEC);
    if (in_fd == -1) {
        PLOGE("stage: open src %s", src.c_str());
        return false;
    }

    int out_fd = open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (out_fd == -1) {
        PLOGE("stage: open dst %s", dst.c_str());
        close(in_fd);
        return false;
    }

    char buf[32768];
    bool ok = true;
    for (;;) {
        ssize_t nread = read(in_fd, buf, sizeof(buf));
        if (nread == 0) break;
        if (nread == -1) {
            if (errno == EINTR) continue;
            PLOGE("stage: read %s", src.c_str());
            ok = false;
            break;
        }
        ssize_t written = 0;
        while (written < nread) {
            ssize_t nwrite = write(out_fd, buf + written, static_cast<size_t>(nread - written));
            if (nwrite == -1) {
                if (errno == EINTR) continue;
                PLOGE("stage: write %s", dst.c_str());
                ok = false;
                break;
            }
            written += nwrite;
        }
        if (!ok) break;
    }

    if (ok && fchmod(out_fd, mode) == -1) {
        LOGW("stage: fchmod %s failed: %s (%d)", dst.c_str(), strerror(errno), errno);
    }
    close(in_fd);
    if (close(out_fd) == -1) {
        PLOGE("stage: close %s", dst.c_str());
        ok = false;
    }
    if (!ok) {
        unlink(dst.c_str());
    }
    return ok;
}

// Install a library without disturbing the copy a running process may already have mapped.
// Writing in place would either fail with ETXTBSY or mutate a mapped file; renaming over it
// publishes the new inode and leaves existing mappings on the old one, which is released
// when the last of those processes exits.
bool install_lib(const std::string &src, const std::string &dst) {
    if (!is_regular_file(src)) return true;

    auto slash = dst.rfind('/');
    if (slash == std::string::npos) return false;
    if (!create_sys_perm(dst.substr(0, slash))) return false;

    std::string tmp = dst + ".new";
    if (!copy_file(src, tmp, 0644)) return false;

    if (chmod(tmp.c_str(), 0644) == -1) {
        LOGW("stage: chmod 0644 %s failed: %s (%d)", tmp.c_str(), strerror(errno), errno);
    }
    set_selinux_context(tmp, kSystemFileContext);
    if (chown(tmp.c_str(), kAidSystem, kGidSystem) == -1) {
        LOGW("stage: chown system:system %s failed: %s (%d)", tmp.c_str(), strerror(errno), errno);
    }
    if (rename(tmp.c_str(), dst.c_str()) == -1) {
        PLOGE("stage: rename %s -> %s", tmp.c_str(), dst.c_str());
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

void detach_stdio() {
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO) close(devnull);
    }
}

void run_shell_script(const std::string &cwd, const std::string &script, const char *arg,
                      bool async) {
    if (async) {
        pid_t child = fork_dont_care();
        if (child == 0) {
            detach_stdio();
            if (!cwd.empty()) (void) chdir(cwd.c_str());
            if (arg != nullptr) {
                execl("/system/bin/sh", "sh", script.c_str(), arg, nullptr);
            } else {
                execl("/system/bin/sh", "sh", script.c_str(), nullptr);
            }
            PLOGE("stage: exec sh %s", script.c_str());
            _exit(127);
        }
        return;
    }

    pid_t child = fork();
    if (child == 0) {
        if (!cwd.empty()) (void) chdir(cwd.c_str());
        if (arg != nullptr) {
            execl("/system/bin/sh", "sh", script.c_str(), arg, nullptr);
        } else {
            execl("/system/bin/sh", "sh", script.c_str(), nullptr);
        }
        PLOGE("stage: exec sh %s", script.c_str());
        _exit(127);
    } else if (child > 0) {
        int status = 0;
        while (waitpid(child, &status, 0) == -1 && errno == EINTR) {
        }
    } else {
        PLOGE("stage: fork for %s", script.c_str());
    }
}

void run_spoof_props(const std::string &moddir, const char *stage_arg, bool async) {
    std::string script = moddir + "/spoof-props.sh";
    if (!is_regular_file(script)) return;
    run_shell_script(moddir, script, stage_arg, async);
}

std::string resolve_self_exe() {
    char buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len <= 0) {
        PLOGE("stage: readlink /proc/self/exe");
        return "";
    }
    buf[len] = '\0';
    return std::string(buf, static_cast<size_t>(len));
}

bool bootstrap_monitor(const std::string &moddir) {
    const std::string &work_dir = zygiskd::GetTmpPath();

    // The work directory is deliberately not wiped. On a late load or a soft reboot a monitor
    // from the previous root session may still own the control socket here, and removing it
    // would leave that monitor unreachable while injected processes keep running. A stale
    // socket from a dead monitor is unlinked by the next monitor when it binds.
    bool first_init = !is_dir(work_dir);
    if (!create_sys_perm(work_dir)) return false;

    const std::string dst_spoof = work_dir + "/spoof.prop";
    const std::string src_spoof = moddir + "/spoof.prop";
    if (first_init && !is_regular_file(dst_spoof) && is_regular_file(src_spoof)) {
        copy_file(src_spoof, dst_spoof, 0600);
    }
    if (is_regular_file(dst_spoof)) {
        if (chmod(dst_spoof.c_str(), 0600) == -1) {
            LOGW("stage: chmod 0600 %s failed: %s (%d)", dst_spoof.c_str(), strerror(errno), errno);
        }
        set_selinux_context(dst_spoof, kSystemFileContext);
        if (chown(dst_spoof.c_str(), kAidRoot, kGidRoot) == -1) {
            LOGW("stage: chown root:root %s failed: %s (%d)", dst_spoof.c_str(), strerror(errno),
                 errno);
        }
    }

    install_lib(moddir + "/lib64/libzygisk.so", work_dir + "/lib64/libzygisk.so");
    install_lib(moddir + "/lib/libzygisk.so", work_dir + "/lib/libzygisk.so");

    std::string self_exe = resolve_self_exe();
    if (self_exe.empty()) return false;

    // Unconditional: the monitor enforces the single-owner invariant itself and a redundant
    // one exits immediately, so neither this stage nor a soft reboot has to probe for it.
    pid_t child = fork_dont_care();
    if (child == 0) {
        detach_stdio();
#ifdef ZYGISK_DEBUG
        setenv("RUST_BACKTRACE", "1", 1);
#endif
        execl(self_exe.c_str(), self_exe.c_str(), "monitor", nullptr);
        PLOGE("stage: exec monitor %s", self_exe.c_str());
        _exit(1);
    } else if (child == -1) {
        PLOGE("stage: fork monitor");
        return false;
    }

    // Wait until the monitor has seized init and bound its control socket before returning.
    // Without this handshake, a fast soft reboot can fork zygote before the backgrounded
    // monitor finishes PTRACE_SEIZE on PID 1 and miss injection entirely.
    if (!wait_for_monitor()) {
        LOGW("stage: timed out waiting for monitor control socket");
    }
    return true;
}

void fan_out_modules(const std::string &moddir, const char *script_name, bool async) {
    auto slash = moddir.rfind('/');
    if (slash == std::string::npos || slash == 0) return;

    std::string modules_dir = moddir.substr(0, slash);
    std::string self_name = moddir.substr(slash + 1);

    auto dir = std::unique_ptr<DIR, decltype(&closedir)>(opendir(modules_dir.c_str()), &closedir);
    if (!dir) return;

    while (auto *entry = readdir(dir.get())) {
        std::string_view name(entry->d_name);
        if (name == "."sv || name == ".."sv || name == self_name) continue;

        std::string mod_path = modules_dir + "/" + std::string(name);
        if (!is_dir(mod_path) || !is_dir(mod_path + "/zygisk")) continue;
        if (path_exists(mod_path + "/disable") || path_exists(mod_path + "/remove")) continue;

        std::string script_path = mod_path + "/" + script_name;
        if (!is_regular_file(script_path)) continue;

        LOGI("Manually trigger %s for %s", script_name, mod_path.c_str());
        run_shell_script(mod_path, script_path, nullptr, async);
    }
}

std::vector<pid_t> find_other_tracers(const std::string &moddir) {
    std::vector<pid_t> found;
    pid_t self_pid = getpid();
    std::string mod_bin_prefix = moddir + "/bin/";

    auto dir = std::unique_ptr<DIR, decltype(&closedir)>(opendir("/proc"), &closedir);
    if (!dir) return found;

    while (auto *entry = readdir(dir.get())) {
        char *end_ptr = nullptr;
        errno = 0;
        long value = strtol(entry->d_name, &end_ptr, 10);
        if (*end_ptr != '\0' || errno != 0 || value <= 0) continue;
        auto pid = static_cast<pid_t>(value);
        if (pid == self_pid) continue;

        std::string exe_link = "/proc/" + std::string(entry->d_name) + "/exe";
        char buf[PATH_MAX];
        ssize_t len = readlink(exe_link.c_str(), buf, sizeof(buf) - 1);
        if (len <= 0) continue;
        buf[len] = '\0';
        std::string_view exe(buf, static_cast<size_t>(len));

        bool is_ours =
            (exe.starts_with(mod_bin_prefix) && exe.find("zygisk-ptrace") != std::string_view::npos) ||
            (exe.find("/hot_install_trash/") != std::string_view::npos &&
             exe.find("/bin/zygisk-ptrace") != std::string_view::npos);
        if (is_ours) {
            found.push_back(pid);
        }
    }
    return found;
}

void stop_monitor(const std::string &moddir, int max_wait_ms) {
    // Only one process may trace init, so the next monitor cannot seize it until the old one
    // has exited. Releasing the control socket is not enough: the ptrace attachment outlives
    // it until the process dies, which is also when the daemon follows through PR_SET_PDEATHSIG.
    send_control_command(EXIT, /*quiet=*/true);

    constexpr int kPollStepMs = 20;
    for (int waited = 0; waited < max_wait_ms; waited += kPollStepMs) {
        if (get_tracer_pid(1) <= 0 && find_other_tracers(moddir).empty()) {
            return;
        }
        usleep(kPollStepMs * 1000);
    }

    // Fallback if the control socket was unreachable or the monitor hung: terminate only
    // tracer processes running from our own module directory (or a stashed hot-install copy).
    auto remaining = find_other_tracers(moddir);
    if (remaining.empty()) return;

    for (pid_t pid : remaining) {
        kill(pid, SIGTERM);
    }
    for (int waited = 0; waited < 500; waited += kPollStepMs) {
        if (get_tracer_pid(1) <= 0 && find_other_tracers(moddir).empty()) {
            return;
        }
        usleep(kPollStepMs * 1000);
    }

    for (pid_t pid : find_other_tracers(moddir)) {
        kill(pid, SIGKILL);
    }
}

int stage_post_fs_data(const std::string &moddir) {
    if (!bootstrap_monitor(moddir)) return EXIT_FAILURE;

    if (!caller_fans_out() && on_path("magisk")) {
        fan_out_modules(moddir, "post-fs-data.sh", /*async=*/false);
    }
    return EXIT_SUCCESS;
}

int stage_post_mount() {
    // Gate on a live zygote so a normal boot stays silent.
    if (find_zygotes().empty()) {
        return EXIT_SUCCESS;
    }

    LOGI("post-mount: system already running, arming NyaZygisk");

    RearmResult result = RearmResult::Failed;
    if (!send_rearm_command(result, /*quiet=*/true)) {
        LOGE("post-mount: no monitor answered, injection not armed");
        return EXIT_FAILURE;
    }

    LOGI("post-mount: rearm result = %s", rearm_result_name(result));
    return result == RearmResult::Failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

int stage_service(const std::string &moddir) {
    run_spoof_props(moddir, "late", /*async=*/true);

    // ksud and apd run every enabled module's service.sh themselves, and announce themselves
    // through KSU and APATCH. Magisk runs only those of the modules it mounts, which leaves out
    // the Zygisk-only ones, and a build with no root framework runs none at all, so fan out
    // whenever nothing else will.
    if (!caller_fans_out()) {
        fan_out_modules(moddir, "service.sh", /*async=*/true);
    }

    // Idempotent safety net for Magisk (which has no post-mount stage) and devices with
    // persist.sys.zygote.early enabled. AlreadyHooked returns immediately at negligible cost.
    if (!find_zygotes().empty()) {
        RearmResult result = RearmResult::Failed;
        if (send_rearm_command(result, /*quiet=*/true)) {
            LOGI("service: rearm result = %s", rearm_result_name(result));
        } else {
            LOGW("service: no monitor answered rearm");
        }
    }
    return EXIT_SUCCESS;
}

int stage_hotinstall(const std::string &moddir) {
    if (path_exists(moddir + "/disable")) {
        return EXIT_SUCCESS;
    }

    if (monitor_is_running() || get_tracer_pid(1) > 0) {
        printf("- Stopping the previous monitor\n");
        fflush(stdout);
    }
    stop_monitor(moddir, 4000);

    printf("- Starting the new monitor\n");
    fflush(stdout);
    if (!bootstrap_monitor(moddir)) {
        printf("! Failed to start the new monitor, NyaZygisk will start on the next boot\n");
        return EXIT_FAILURE;
    }

    RearmResult result = RearmResult::Failed;
    if (!send_rearm_command(result, /*quiet=*/true) || result == RearmResult::Failed) {
        printf("! The new monitor did not answer, NyaZygisk will start on the next boot\n");
        return EXIT_FAILURE;
    }

    printf("- The new monitor is armed; zygote keeps the running injector until it restarts\n");
    return EXIT_SUCCESS;
}

int stage_late_load(const std::string &moddir) {
    LOGI("late-load: bootstrapping NyaZygisk on a running system");
    if (!bootstrap_monitor(moddir)) return EXIT_FAILURE;

    int rc = stage_post_mount();
    if (!caller_fans_out()) {
        LOGI("late-load: no root framework, running the service stage");
        stage_service(moddir);
    }
    return rc;
}

int stage_soft_reboot(const std::string &moddir) {
    stop_monitor(moddir, 4000);
    return EXIT_SUCCESS;
}

}  // namespace

int handle_stage(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
                "error: stage command requires a stage name "
                "(post-fs-data|post-mount|service|hotinstall|late-load|soft-reboot)\n");
        return EXIT_FAILURE;
    }

    const auto stage = std::string_view(argv[2]);
    const std::string &moddir = get_module_dir();

    if (stage == "soft-reboot"sv) {
        return stage_soft_reboot(moddir);
    }

    if (should_stand_down()) {
        return EXIT_SUCCESS;
    }

    if (stage == "post-fs-data"sv) {
        return stage_post_fs_data(moddir);
    } else if (stage == "post-mount"sv) {
        return stage_post_mount();
    } else if (stage == "service"sv) {
        return stage_service(moddir);
    } else if (stage == "hotinstall"sv) {
        return stage_hotinstall(moddir);
    } else if (stage == "late-load"sv) {
        return stage_late_load(moddir);
    }

    fprintf(stderr, "error: unknown stage '%s'\n", argv[2]);
    return EXIT_FAILURE;
}

int handle_status() {
    const std::string prop_path = zygiskd::GetTmpPath() + "/module.prop";
    auto file = std::unique_ptr<FILE, decltype(&fclose)>(fopen(prop_path.c_str(), "re"), &fclose);
    if (!file) {
        printf("NyaZygisk: not running (missing %s)\n", prop_path.c_str());
        return EXIT_FAILURE;
    }

    printf("monitor_socket=%s\n", monitor_is_running() ? "alive" : "dead");
    printf("init_tracer_pid=%d\n", get_tracer_pid(1));

    char line[1024];
    while (fgets(line, sizeof(line), file.get()) != nullptr) {
        std::string_view sv(line);
        if (sv.starts_with("version="sv) || sv.starts_with("versionCode="sv) ||
            sv.starts_with("description="sv) || sv.starts_with("monitor_status="sv) ||
            sv.starts_with("monitor_stop_reason="sv) || sv.starts_with("zygote_"sv) ||
            sv.starts_with("daemon_"sv)) {
            fputs(line, stdout);
        }
    }
    return EXIT_SUCCESS;
}
