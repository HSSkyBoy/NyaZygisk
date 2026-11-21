#include "zn_hook.hpp"

#include <dlfcn.h>
#include <linux/memfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <tuple>
#include <vector>

#if defined(__riscv)
#include <dobby_compat.h>
#else
#include <bytehook.h>
#include <dobby.h>
#endif

#include <lsplt.hpp>

#include "elf_util.h"
#include "linker.hpp"
#include "logging.hpp"
#include "zygisk.hpp"

namespace zn::hook {

namespace {

std::atomic<PltEngine> g_plt_engine{PltEngine::kByteHook};
std::atomic<bool> g_plt_engine_initialized{false};

#ifndef __riscv
std::once_flag g_bytehook_init_once;
int g_bytehook_init_result = -1;

bool bytehookInit() {
    std::call_once(g_bytehook_init_once, [] {
        g_bytehook_init_result = bytehook_init(BYTEHOOK_MODE_MANUAL, false);
        if (g_bytehook_init_result == 0) {
            LOGI("ZN hook: ByteHook engine initialized successfully");
        }
    });
    if (g_bytehook_init_result != 0) {
        LOGE("ZN hook: bytehook_init failed: %d", g_bytehook_init_result);
        return false;
    }
    return true;
}

extern "C" void bytehookHookedCallback(bytehook_stub_t stub, int status_code,
                                       const char* caller_path_name, const char* sym_name,
                                       void* new_func, void* prev_func, void* arg) {
    (void)stub;
    (void)caller_path_name;
    (void)sym_name;
    (void)new_func;
    // Handle both ORIG_ADDR (fired before the GOT write) and OK (after) so the
    // dispatch slot is populated before any concurrent caller can enter the hook.
    if ((status_code == BYTEHOOK_STATUS_CODE_ORIG_ADDR ||
         status_code == BYTEHOOK_STATUS_CODE_OK) &&
        prev_func != nullptr) {
        auto* out = static_cast<void**>(arg);
        if (out != nullptr && __atomic_load_n(out, __ATOMIC_RELAXED) == nullptr) {
            __atomic_store_n(out, prev_func, __ATOMIC_RELEASE);
        }
    }
}
#endif

// ---------------------------------------------------------------------------
// Paired RX / RW Tail-Jump Stub Pool
//
// Each slab maps 2 contiguous pages:
//   [base,      base + pg) : immutable PROT_READ | PROT_EXEC dispatch stubs
//   [base + pg, base + 2pg): permanently PROT_READ | PROT_WRITE void* target slots
//
// Every stub performs an ABI-transparent tail jump to *slot (preserving all
// argument/FP registers, stack layout, and return address). Updating a chain
// head or next link is a single atomic pointer store on the RW page — no
// mprotect, no W+X pages, and no icache flush on subsequent hooks/unhooks.
// Slabs are intentionally retained for process lifetime so in-flight threads
// executing a stub can never fault after an unhook.
// ---------------------------------------------------------------------------

struct StubSlot {
    void* code = nullptr;
    void** data = nullptr;

    explicit operator bool() const { return code != nullptr && data != nullptr; }
};

class StubPool {
public:
    static constexpr size_t kSlotSize = 16;

    static StubSlot alloc(void* initial_target) {
        std::lock_guard<std::mutex> lk(mutex_);
        if (slabs_.empty() || slabs_.back().next_idx >= slabs_.back().capacity) {
            if (!allocateSlabLocked()) {
                return {};
            }
        }
        Slab& slab = slabs_.back();
        const size_t idx = slab.next_idx++;
        StubSlot slot;
        slot.code = reinterpret_cast<void*>(slab.code_base + idx * kSlotSize);
        slot.data = reinterpret_cast<void**>(slab.data_base) + idx;
        __atomic_store_n(slot.data, initial_target, __ATOMIC_RELEASE);
        return slot;
    }

private:
    struct Slab {
        uintptr_t code_base = 0;
        uintptr_t data_base = 0;
        size_t capacity = 0;
        size_t next_idx = 0;
    };

    static bool emitTailJump(uint8_t* code, uintptr_t code_addr, uintptr_t data_addr) {
#if defined(__aarch64__)
        const int64_t delta = static_cast<int64_t>(data_addr) - static_cast<int64_t>(code_addr + 4);
        if ((delta & 3) != 0 || delta < -(1LL << 20) || delta >= (1LL << 20)) {
            return false;
        }
        const uint32_t imm19 = static_cast<uint32_t>(delta >> 2) & 0x7ffffu;
        const uint32_t insns[4] = {
            0xd50324dfu,                     // bti jc (NOP without FEAT_BTI)
            0x58000010u | (imm19 << 5),      // ldr x16, [pc, #delta]
            0xd61f0200u,                     // br  x16 (BTI-c compatible)
            0xd503201fu,                     // nop
        };
        memcpy(code, insns, sizeof(insns));
        return true;
#elif defined(__arm__)
        (void)code_addr;
        // ARM-mode interworking stub: reaches any 32-bit data_addr regardless of page size
        // and branches cleanly to both ARM (bit0=0) and Thumb (bit0=1) targets.
        const uint32_t insns[4] = {
            0xe59fc004u,                          // ldr ip, [pc, #4]  (loads data_addr at +12)
            0xe59cc000u,                          // ldr ip, [ip, #0]  (loads *data_addr)
            0xe12fff1cu,                          // bx  ip
            static_cast<uint32_t>(data_addr),     // .word data_addr
        };
        memcpy(code, insns, sizeof(insns));
        return true;
#elif defined(__x86_64__)
        const int64_t disp = static_cast<int64_t>(data_addr) - static_cast<int64_t>(code_addr + 10);
        if (disp < INT32_MIN || disp > INT32_MAX) {
            return false;
        }
        const int32_t disp32 = static_cast<int32_t>(disp);
        memset(code, 0x90, kSlotSize);
        code[0] = 0xf3;  // endbr64
        code[1] = 0x0f;
        code[2] = 0x1e;
        code[3] = 0xfa;
        code[4] = 0xff;  // jmp qword ptr [rip + disp32]
        code[5] = 0x25;
        memcpy(code + 6, &disp32, sizeof(disp32));
        return true;
#elif defined(__i386__)
        (void)code_addr;
        const uint32_t abs_addr = static_cast<uint32_t>(data_addr);
        memset(code, 0x90, kSlotSize);
        code[0] = 0xff;  // jmp dword ptr [abs_addr]
        code[1] = 0x25;
        memcpy(code + 2, &abs_addr, sizeof(abs_addr));
        return true;
#elif defined(__riscv) && __riscv_xlen == 64
        const int64_t delta = static_cast<int64_t>(data_addr) - static_cast<int64_t>(code_addr);
        if (delta < -(1LL << 31) || delta >= (1LL << 31) - 0x800) {
            return false;
        }
        const int32_t hi20 = static_cast<int32_t>((delta + 0x800) & ~0xfffLL);
        const int32_t lo12 = static_cast<int32_t>(delta - hi20);
        const uint32_t insns[4] = {
            static_cast<uint32_t>(hi20) | (6u << 7) | 0x17u,                        // auipc t1, hi20
            ((static_cast<uint32_t>(lo12) & 0xfffu) << 20) | (6u << 15) | (3u << 12) |
                (6u << 7) | 0x03u,                                                  // ld t1, lo12(t1)
            (6u << 15) | 0x67u,                                                     // jr t1
            0x00000013u,                                                            // nop
        };
        memcpy(code, insns, sizeof(insns));
        return true;
#else
        (void)code;
        (void)code_addr;
        (void)data_addr;
        return false;
#endif
    }

    static bool mapCodeViaMemfd(uintptr_t code_base, size_t pg) {
        int mfd = static_cast<int>(syscall(__NR_memfd_create, "jit-cache", MFD_CLOEXEC));
        if (mfd < 0) {
            PLOGE("ZN hook: memfd_create for stub slab failed");
            return false;
        }
        const auto* src = reinterpret_cast<const uint8_t*>(code_base);
        size_t written = 0;
        while (written < pg) {
            ssize_t n = write(mfd, src + written, pg - written);
            if (n > 0) {
                written += static_cast<size_t>(n);
            } else if (n < 0 && errno == EINTR) {
                continue;
            } else {
                PLOGE("ZN hook: write stub slab memfd failed");
                close(mfd);
                return false;
            }
        }
        void* rx = mmap(reinterpret_cast<void*>(code_base), pg, PROT_READ | PROT_EXEC,
                        MAP_PRIVATE | MAP_FIXED, mfd, 0);
        close(mfd);
        if (rx == MAP_FAILED) {
            PLOGE("ZN hook: mmap(PROT_READ|PROT_EXEC) stub slab memfd failed");
            return false;
        }
        __builtin___clear_cache(reinterpret_cast<char*>(code_base),
                                reinterpret_cast<char*>(code_base + pg));
        return true;
    }

    static bool allocateSlabLocked() {
        long raw_pg = sysconf(_SC_PAGESIZE);
        const size_t pg = raw_pg > 0 ? static_cast<size_t>(raw_pg) : 4096;
        void* mem = mmap(nullptr, pg * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) {
            PLOGE("ZN hook: mmap stub slab failed");
            return false;
        }

        const uintptr_t code_base = reinterpret_cast<uintptr_t>(mem);
        const uintptr_t data_base = code_base + pg;
        const size_t cap_code = pg / kSlotSize;
        const size_t cap_data = pg / sizeof(void*);
        const size_t capacity = cap_code < cap_data ? cap_code : cap_data;

        for (size_t i = 0; i < capacity; ++i) {
            const uintptr_t caddr = code_base + i * kSlotSize;
            const uintptr_t daddr = data_base + i * sizeof(void*);
            if (!emitTailJump(reinterpret_cast<uint8_t*>(caddr), caddr, daddr)) {
                munmap(mem, pg * 2);
                LOGE("ZN hook: failed to emit tail-jump stub");
                return false;
            }
        }

        __builtin___clear_cache(reinterpret_cast<char*>(code_base),
                                reinterpret_cast<char*>(code_base + pg));

        if (mprotect(reinterpret_cast<void*>(code_base), pg, PROT_READ | PROT_EXEC) != 0) {
            // Restricted domains such as system_server deny anonymous execmem; fall back to
            // a file-backed RX mapping from a closed memfd ("jit-cache") while preserving
            // the adjacent anonymous RW slot page at code_base + pg.
            if (!mapCodeViaMemfd(code_base, pg)) {
                munmap(mem, pg * 2);
                return false;
            }
        }

        register_cfi_unchecked(code_base, pg);

        slabs_.push_back(Slab{code_base, data_base, capacity, 0});
        LOGV("ZN hook: allocated RX/RW stub slab at %p (capacity=%zu)", mem, capacity);
        return true;
    }

    static inline std::mutex mutex_;
    static inline std::vector<Slab> slabs_;
};

// ---------------------------------------------------------------------------
// Caller DSO identification (for out-of-order inlineUnhook)
// ---------------------------------------------------------------------------

struct DsoIdentity {
    enum class Kind { kNone, kCustomImage, kDlBase, kMapInode, kMapRange };
    Kind kind = Kind::kNone;
    uintptr_t a = 0;
    uintptr_t b = 0;

    bool valid() const { return kind != Kind::kNone; }
    bool operator==(const DsoIdentity& o) const { return kind == o.kind && a == o.a && b == o.b; }
};

DsoIdentity identifyDso(const void* ptr, const std::vector<znn::MapEntry>* cached_maps) {
    if (!ptr) return {};
    uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
#if defined(__arm__)
    addr &= ~uintptr_t{1};
#endif

    if (auto img = linker::FindImageByAddress(reinterpret_cast<const void*>(addr))) {
        return {DsoIdentity::Kind::kCustomImage, img->map_start(), img->size()};
    }

    Dl_info info{};
    if (dladdr(reinterpret_cast<const void*>(addr), &info) != 0 && info.dli_fbase != nullptr) {
        return {DsoIdentity::Kind::kDlBase, reinterpret_cast<uintptr_t>(info.dli_fbase), 0};
    }

    std::vector<znn::MapEntry> local_maps;
    const auto& maps = cached_maps ? *cached_maps : (local_maps = znn::parseMaps("self"));
    for (const auto& m : maps) {
        if (addr >= m.start && addr < m.end) {
            if (m.inode != 0) {
                return {DsoIdentity::Kind::kMapInode, static_cast<uintptr_t>(m.dev),
                        static_cast<uintptr_t>(m.inode)};
            }
            return {DsoIdentity::Kind::kMapRange, m.start, m.end};
        }
    }
    return {};
}

// ---------------------------------------------------------------------------
// Inline Hook Chain Manager
// ---------------------------------------------------------------------------

struct InlineNode {
    void* handler = nullptr;
    StubSlot next_slot;
};

struct InlineChain {
    void* raw_target = nullptr;
    void* real_orig = nullptr;
    StubSlot head_slot;
    // Front = most recently installed hook (invoked first by head_slot).
    std::deque<InlineNode> nodes;
};

std::mutex g_inline_mutex;
std::map<uintptr_t, InlineChain> g_inline_chains;

uintptr_t normalizeTargetKey(void* target) {
    uintptr_t key = reinterpret_cast<uintptr_t>(target);
#if defined(__arm__)
    key &= ~uintptr_t{1};
#endif
    return key;
}

// ---------------------------------------------------------------------------
// PLT Hook Chain Manager
// ---------------------------------------------------------------------------

struct PltKey {
    dev_t dev = 0;
    ino_t inode = 0;
    std::string symbol;

    bool operator<(const PltKey& o) const {
        return std::tie(dev, inode, symbol) < std::tie(o.dev, o.inode, o.symbol);
    }
};

struct PltNode {
    void* handler = nullptr;
    StubSlot next_slot;   // Used when chain->uses_stub == true
    void* direct_prev = nullptr;  // Used when chain->uses_stub == false
};

struct PltChain {
    PltEngine backend = PltEngine::kLsplt;
    bool uses_stub = false;
    void* real_orig = nullptr;
    StubSlot head_slot;
#ifndef __riscv
    bytehook_stub_t bh_stub = nullptr;
#endif
    // Front = most recently installed hook (invoked first).
    std::deque<PltNode> nodes;
};

std::mutex g_plt_mutex;
std::map<PltKey, PltChain> g_plt_chains;

const znn::MapEntry* findTargetEntry(const std::vector<znn::MapEntry>& maps, uintptr_t base) {
    const znn::MapEntry* hit = nullptr;
    for (const auto& m : maps) {
        if (m.inode == 0) continue;
        if ((base >= m.start && base < m.end) ||
            (m.start >= m.offset && base == m.start - m.offset)) {
            hit = &m;
            break;
        }
    }
    if (!hit) return nullptr;
    for (const auto& m : maps) {
        if (m.dev == hit->dev && m.inode == hit->inode && m.offset == 0) return &m;
    }
    return hit;
}

bool lspltPatchRaw(dev_t dev, ino_t inode, const char* symbol, void* replacement, void** backup_out) {
    void* backup = nullptr;
    if (!lsplt::RegisterHook(dev, inode, symbol, replacement, &backup)) {
        LOGE("ZN pltHook %s: RegisterHook failed", symbol);
        return false;
    }
    if (!lsplt::CommitHook()) {
        LOGE("ZN pltHook %s: CommitHook failed", symbol);
        return false;
    }
    if (backup_out != nullptr) {
        if (backup == nullptr) {
            LOGE("ZN pltHook %s: symbol not found in PLT", symbol);
            return false;
        }
        __atomic_store_n(backup_out, backup, __ATOMIC_RELEASE);
    }
    return true;
}

bool installPltBackend(const znn::MapEntry& entry, const char* symbol, void* got_target,
                       void** orig_out, PltChain& chain) {
#ifndef __riscv
    if (getPltEngine() == PltEngine::kByteHook && bytehookInit()) {
        const bytehook_stub_t stub =
            bytehook_hook_single(entry.path.c_str(), nullptr, symbol, got_target,
                                 bytehookHookedCallback, orig_out);
        if (stub != nullptr) {
            void* orig = __atomic_load_n(orig_out, __ATOMIC_ACQUIRE);
            if (orig != nullptr) {
                chain.backend = PltEngine::kByteHook;
                chain.bh_stub = stub;
                chain.real_orig = orig;
                return true;
            }
            LOGW("ZN pltHook %s: ByteHook found no matching relocation in %s, falling back to LSPlt",
                 symbol, entry.path.c_str());
            bytehook_unhook(stub);
        } else {
            LOGW("ZN pltHook %s: bytehook_hook_single failed for %s, falling back to LSPlt",
                 symbol, entry.path.c_str());
        }
    }
#endif

    if (lspltPatchRaw(entry.dev, entry.inode, symbol, got_target, orig_out)) {
        chain.backend = PltEngine::kLsplt;
        chain.real_orig = __atomic_load_n(orig_out, __ATOMIC_ACQUIRE);
        return true;
    }
    return false;
}

bool uninstallPltBackend(const PltKey& key, PltChain& chain) {
#ifndef __riscv
    if (chain.backend == PltEngine::kByteHook && chain.bh_stub != nullptr) {
        if (bytehook_unhook(chain.bh_stub) != 0) {
            LOGE("ZN pltHook %s: bytehook_unhook failed", key.symbol.c_str());
            return false;
        }
        chain.bh_stub = nullptr;
        return true;
    }
#endif
    return lspltPatchRaw(key.dev, key.inode, key.symbol.c_str(), chain.real_orig, nullptr);
}

}  // namespace

void setPltEngine(PltEngine e) {
    g_plt_engine.store(e, std::memory_order_release);
    g_plt_engine_initialized.store(true, std::memory_order_release);
}

#define _ZN_HOOK_STR(x) #x
#define ZN_HOOK_STR(x) _ZN_HOOK_STR(x)
#ifdef WORK_DIRECTORY
constexpr const char* kZnConfigPath = ZN_HOOK_STR(WORK_DIRECTORY) "/config.prop";
#else
constexpr const char* kZnConfigPath = "/data/system_de/nyazygisk/config.prop";
#endif

void initPltEngineFromConfig() {
    g_plt_engine_initialized.store(true, std::memory_order_release);
    FILE* fp = fopen(kZnConfigPath, "re");
    if (!fp) return;
    char line[128];
    while (fgets(line, sizeof(line), fp)) {
        char* end = line + strlen(line);
        while (end > line &&
               (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' ' || end[-1] == '\t')) {
            *--end = '\0';
        }
        if (strcmp(line, "plt_engine=lsplt") == 0) {
            g_plt_engine.store(PltEngine::kLsplt, std::memory_order_release);
            break;
        } else if (strcmp(line, "plt_engine=bytehook") == 0) {
            g_plt_engine.store(PltEngine::kByteHook, std::memory_order_release);
            break;
        }
    }
    fclose(fp);
    LOGI("ZN hook: selected PLT engine: %s",
         g_plt_engine.load(std::memory_order_acquire) == PltEngine::kByteHook ? "ByteHook"
                                                                              : "LSPlt");
}

PltEngine getPltEngine() {
    if (!g_plt_engine_initialized.load(std::memory_order_acquire)) {
        initPltEngineFromConfig();
    }
    return g_plt_engine.load(std::memory_order_acquire);
}

bool hasActiveHooks() {
#ifndef __riscv
    if (g_bytehook_init_result == 0) return true;
#endif
    {
        std::lock_guard<std::mutex> lk(g_inline_mutex);
        if (!g_inline_chains.empty()) return true;
    }
    {
        std::lock_guard<std::mutex> lk(g_plt_mutex);
        if (!g_plt_chains.empty()) return true;
    }
    return false;
}

bool inlineHook(void* target, void* addr, void** original) {
    if (!target || !addr) return false;

    const uintptr_t key = normalizeTargetKey(target);
    std::lock_guard<std::mutex> lk(g_inline_mutex);

    auto it = g_inline_chains.find(key);
    if (it != g_inline_chains.end()) {
        InlineChain& chain = it->second;
        if (addr == chain.head_slot.code || addr == chain.raw_target) {
            LOGW("ZN inlineHook %p: rejecting recursive handler %p", target, addr);
            return false;
        }
        for (const auto& node : chain.nodes) {
            if (node.handler == addr) {
                LOGW("ZN inlineHook %p: handler %p is already in hook chain", target, addr);
                return false;
            }
        }

        void* prev_head = __atomic_load_n(chain.head_slot.data, __ATOMIC_ACQUIRE);
        StubSlot next_slot = StubPool::alloc(prev_head);
        if (!next_slot) {
            LOGE("ZN inlineHook %p: failed to allocate chain slot", target);
            return false;
        }

        // Publish *original before switching the head so a concurrent thread entering
        // `addr` immediately observes a valid trampoline to the previous hook.
        if (original != nullptr) {
            *original = next_slot.code;
        }
        chain.nodes.push_front(InlineNode{addr, next_slot});
        __atomic_store_n(chain.head_slot.data, addr, __ATOMIC_RELEASE);

        LOGI("ZN inlineHook %p: chained handler %p (depth=%zu)", target, addr, chain.nodes.size());
        return true;
    }

    // First hook on this target address: install a single Dobby/rv64hook detour to head_slot.
    StubSlot head_slot = StubPool::alloc(addr);
    StubSlot next_slot = StubPool::alloc(nullptr);
    if (!head_slot || !next_slot) {
        LOGW("ZN inlineHook %p: stub pool unavailable, falling back to direct hook", target);
        return DobbyHook(target, reinterpret_cast<dobby_dummy_func_t>(addr),
                         reinterpret_cast<dobby_dummy_func_t*>(original)) == RT_SUCCESS;
    }

    // Pre-publish *original and let Dobby write the relocated trampoline directly into
    // *next_slot.data BEFORE routing->Commit() patches `target`.
    if (original != nullptr) {
        *original = next_slot.code;
    }
    if (DobbyHook(target, reinterpret_cast<dobby_dummy_func_t>(head_slot.code),
                  reinterpret_cast<dobby_dummy_func_t*>(next_slot.data)) != RT_SUCCESS) {
        if (original != nullptr) *original = nullptr;
        LOGE("ZN inlineHook %p: underlying inline hook failed", target);
        return false;
    }

    void* real_orig = __atomic_load_n(next_slot.data, __ATOMIC_ACQUIRE);
    InlineChain chain;
    chain.raw_target = target;
    chain.real_orig = real_orig;
    chain.head_slot = head_slot;
    chain.nodes.push_front(InlineNode{addr, next_slot});
    g_inline_chains.emplace(key, std::move(chain));

    LOGI("ZN inlineHook %p: installed chain head %p (real_orig=%p)", target, addr, real_orig);
    return true;
}

bool inlineUnhook(void* target, void* caller_addr) {
    if (!target) return false;

    const uintptr_t key = normalizeTargetKey(target);
    std::lock_guard<std::mutex> lk(g_inline_mutex);

    auto it = g_inline_chains.find(key);
    if (it == g_inline_chains.end()) {
        return DobbyDestroy(target) == RT_SUCCESS;
    }

    InlineChain& chain = it->second;
    if (chain.nodes.empty()) {
        g_inline_chains.erase(it);
        return DobbyDestroy(target) == RT_SUCCESS;
    }

    size_t remove_idx = 0;
    if (chain.nodes.size() > 1 && caller_addr != nullptr) {
        const auto maps = znn::parseMaps("self");
        const DsoIdentity caller_dso = identifyDso(caller_addr, &maps);
        if (caller_dso.valid()) {
            for (size_t i = 0; i < chain.nodes.size(); ++i) {
                if (identifyDso(chain.nodes[i].handler, &maps) == caller_dso) {
                    remove_idx = i;
                    break;
                }
            }
        }
    }

    void* next_target = __atomic_load_n(chain.nodes[remove_idx].next_slot.data, __ATOMIC_ACQUIRE);
    if (chain.nodes.size() == 1) {
        __atomic_store_n(chain.head_slot.data, chain.real_orig, __ATOMIC_RELEASE);
        void* raw_target = chain.raw_target;
        g_inline_chains.erase(it);
        bool ok = DobbyDestroy(raw_target) == RT_SUCCESS;
        LOGI("ZN inlineUnhook %p: removed last hook (destroy=%d)", target, ok ? 1 : 0);
        return ok;
    }

    if (remove_idx == 0) {
        __atomic_store_n(chain.head_slot.data, next_target, __ATOMIC_RELEASE);
    } else {
        __atomic_store_n(chain.nodes[remove_idx - 1].next_slot.data, next_target, __ATOMIC_RELEASE);
    }
    void* removed_handler = chain.nodes[remove_idx].handler;
    chain.nodes.erase(chain.nodes.begin() + static_cast<std::ptrdiff_t>(remove_idx));
    LOGI("ZN inlineUnhook %p: unlinked handler %p (remaining=%zu)", target, removed_handler,
         chain.nodes.size());
    return true;
}

bool pltHook(void* base, const char* symbol, void* hook, void** original) {
    if (!base || !symbol || !hook) return false;

    const uintptr_t b = reinterpret_cast<uintptr_t>(base);
    const auto maps = znn::parseMaps("self");
    const znn::MapEntry* entry = findTargetEntry(maps, b);
    if (!entry) {
        LOGE("ZN pltHook %s: base %p not found in maps", symbol, base);
        return false;
    }

    const PltKey key{entry->dev, entry->inode, std::string(symbol)};
    LOGI("ZN pltHook base=%p symbol=%s (path=%s)", base, symbol, entry->path.c_str());

    std::lock_guard<std::mutex> lk(g_plt_mutex);

    auto it = g_plt_chains.find(key);
    if (it != g_plt_chains.end()) {
        PltChain& chain = it->second;

        // 1. Check whether this call is an unhook request (hook == previously returned *original).
        for (size_t i = 0; i < chain.nodes.size(); ++i) {
            const bool matched_stub = chain.uses_stub && chain.nodes[i].next_slot.code == hook;
            const bool matched_direct = !chain.uses_stub && chain.nodes[i].direct_prev == hook;
            const bool matched_single_orig =
                chain.nodes.size() == 1 && hook == chain.real_orig;
            if (!matched_stub && !matched_direct && !matched_single_orig) continue;

            if (chain.nodes.size() == 1) {
                if (chain.uses_stub) {
                    __atomic_store_n(chain.head_slot.data, chain.real_orig, __ATOMIC_RELEASE);
                }
                bool ok = uninstallPltBackend(key, chain);
                void* orig = chain.real_orig;
                g_plt_chains.erase(it);
                if (ok && original != nullptr) *original = orig;
                return ok;
            }

            if (chain.uses_stub) {
                void* next_target =
                    __atomic_load_n(chain.nodes[i].next_slot.data, __ATOMIC_ACQUIRE);
                if (i == 0) {
                    __atomic_store_n(chain.head_slot.data, next_target, __ATOMIC_RELEASE);
                } else {
                    __atomic_store_n(chain.nodes[i - 1].next_slot.data, next_target,
                                     __ATOMIC_RELEASE);
                }
                chain.nodes.erase(chain.nodes.begin() + static_cast<std::ptrdiff_t>(i));
                if (original != nullptr) *original = chain.real_orig;
                LOGI("ZN pltHook %s: unlinked handler from chain (remaining=%zu)", symbol,
                     chain.nodes.size());
                return true;
            } else {
                // Direct GOT mode (no execmem): only safe to pop head without rewriting
                // other modules' saved direct function pointers.
                if (i == 0) {
                    void* restore_to = chain.nodes[0].direct_prev;
                    if (!lspltPatchRaw(entry->dev, entry->inode, symbol, restore_to, nullptr)) {
                        return false;
                    }
                    chain.nodes.pop_front();
                    if (original != nullptr) *original = restore_to;
                    return true;
                }
                LOGW("ZN pltHook %s: cannot out-of-order unhook in no-execmem mode", symbol);
                return false;
            }
        }

        // 2. New module hooking the same (dev, inode, symbol).
        if (chain.uses_stub && hook == chain.head_slot.code) {
            LOGW("ZN pltHook %s: rejecting recursive handler %p", symbol, hook);
            return false;
        }
        for (const auto& node : chain.nodes) {
            if (node.handler == hook) {
                LOGW("ZN pltHook %s: handler %p is already in hook chain", symbol, hook);
                return false;
            }
        }

        if (chain.uses_stub) {
            void* prev_head = __atomic_load_n(chain.head_slot.data, __ATOMIC_ACQUIRE);
            StubSlot next_slot = StubPool::alloc(prev_head);
            if (!next_slot) {
                LOGE("ZN pltHook %s: failed to allocate chain slot", symbol);
                return false;
            }
            if (original != nullptr) *original = next_slot.code;
            chain.nodes.push_front(PltNode{hook, next_slot, nullptr});
            __atomic_store_n(chain.head_slot.data, hook, __ATOMIC_RELEASE);
            LOGI("ZN pltHook %s: chained handler %p (depth=%zu)", symbol, hook, chain.nodes.size());
            return true;
        }

        // No-execmem fallback: directly chain GOT via LSPlt.
#ifndef __riscv
        if (chain.backend == PltEngine::kByteHook && chain.bh_stub != nullptr) {
            // ByteHook manual mode forbids duplicate hooks; hand off cleanly to LSPlt.
            void* prev_head = chain.nodes.front().handler;
            if (!lspltPatchRaw(entry->dev, entry->inode, symbol, hook, nullptr)) {
                return false;
            }
            // Note: do not call bytehook_unhook here because it would overwrite GOT back
            // to real_orig; detach ownership and let LSPlt own final restoration.
            chain.bh_stub = nullptr;
            chain.backend = PltEngine::kLsplt;
            if (original != nullptr) *original = prev_head;
            chain.nodes.push_front(PltNode{hook, {}, prev_head});
            LOGI("ZN pltHook %s: direct-chained handler %p (depth=%zu)", symbol, hook,
                 chain.nodes.size());
            return true;
        }
#endif
        void* prev_got = nullptr;
        if (!lspltPatchRaw(entry->dev, entry->inode, symbol, hook, &prev_got)) {
            return false;
        }
        if (original != nullptr) *original = prev_got;
        chain.nodes.push_front(PltNode{hook, {}, prev_got});
        LOGI("ZN pltHook %s: direct-chained handler %p via LSPlt (depth=%zu)", symbol, hook,
             chain.nodes.size());
        return true;
    }

    // First hook for this (dev, inode, symbol).
    PltChain chain;
    StubSlot head_slot = StubPool::alloc(hook);
    StubSlot next_slot = StubPool::alloc(nullptr);
    if (head_slot && next_slot) {
        chain.uses_stub = true;
        chain.head_slot = head_slot;
        if (original != nullptr) *original = next_slot.code;
        if (!installPltBackend(*entry, symbol, head_slot.code, next_slot.data, chain)) {
            if (original != nullptr) *original = nullptr;
            return false;
        }
        chain.nodes.push_front(PltNode{hook, next_slot, nullptr});
        g_plt_chains.emplace(key, std::move(chain));
        LOGI("ZN pltHook %s: installed stub chain head %p (real_orig=%p)", symbol, hook,
             chain.real_orig);
        return true;
    }

    // No execmem available (e.g. restricted domain): install direct GOT hook without stubs.
    void* direct_orig = nullptr;
    if (!installPltBackend(*entry, symbol, hook, &direct_orig, chain)) {
        return false;
    }
    chain.uses_stub = false;
    if (original != nullptr) *original = direct_orig;
    chain.nodes.push_front(PltNode{hook, {}, direct_orig});
    g_plt_chains.emplace(key, std::move(chain));
    LOGI("ZN pltHook %s: installed direct hook %p (no execmem)", symbol, hook);
    return true;
}

}  // namespace zn::hook
