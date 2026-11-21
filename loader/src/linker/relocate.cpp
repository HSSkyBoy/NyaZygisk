#include "relocate.hpp"

#include "logging.hpp"
#include "reloc_arch.hpp"

namespace linker {

// ---- SLEB128 ---------------------------------------------------------------
// APS2 (DT_ANDROID_REL[A]) encodes its stream as signed LEB128 groups.
static bool ReadSleb128(const uint8_t *&p, const uint8_t *end, int64_t *out) {
    uint64_t value = 0;
    size_t shift = 0;
    uint8_t byte = 0;
    do {
        if (p >= end) return false;
        byte = *p++;
        if (shift < 64) {
            value |= static_cast<uint64_t>(byte & 0x7f) << shift;
        }
        shift += 7;
    } while (byte & 0x80);
    // Sign-extend if the last byte's sign bit is set and we have room.
    if (shift < 64 && (byte & 0x40)) {
        value |= (~uint64_t{0}) << shift;
    }
    *out = static_cast<int64_t>(value);
    return true;
}

// APS2 group flags.
static constexpr uint64_t kGroupedByInfo = 1;
static constexpr uint64_t kGroupedByOffsetDelta = 2;
static constexpr uint64_t kGroupedByAddend = 4;
static constexpr uint64_t kGroupHasAddend = 8;

// Walk the APS2 stream, emitting each decoded relocation through `emit`.
// Mirrors bionic's relocate_packed implementation closely enough for the
// relocation forms modules emit. Works for both REL and RELA (addend ignored
// when the arch is REL-only).
bool ForEachPackedReloc(const uint8_t *stream, size_t size,
                        const std::function<void(ElfW(Addr), uint64_t, int64_t)> &emit) {
    const uint8_t *p = stream;
    const uint8_t *end = stream + size;
    if (size < 4 || p[0] != 'A' || p[1] != 'P' || p[2] != 'S' || p[3] != '2') {
        LOGE("linker: bad APS2 magic");
        return false;
    }
    p += 4;

    // These three accumulate across the WHOLE stream, not per group — matching
    // bionic's for_all_packed_relocs, where `reloc` is a single struct carried
    // through every group. Resetting addend per group (an earlier bug) corrupts
    // IRELATIVE resolver addresses and RELATIVE targets.
    int64_t total = 0;
    int64_t init_offset = 0;
    if (!ReadSleb128(p, end, &total) || !ReadSleb128(p, end, &init_offset) || total < 0) {
        LOGE("linker: truncated or invalid APS2 header");
        return false;
    }
    ElfW(Addr) r_offset = static_cast<ElfW(Addr)>(init_offset);
    uint64_t r_info = 0;
    int64_t r_addend = 0;

    for (int64_t idx = 0; idx < total;) {
        int64_t group_size = 0;
        int64_t raw_flags = 0;
        if (!ReadSleb128(p, end, &group_size) || !ReadSleb128(p, end, &raw_flags) ||
            group_size <= 0 || group_size > total - idx) {
            LOGE("linker: invalid APS2 group header");
            return false;
        }
        const uint64_t flags = static_cast<uint64_t>(raw_flags);

        ElfW(Addr) group_delta = 0;
        if (flags & kGroupedByOffsetDelta) {
            int64_t d = 0;
            if (!ReadSleb128(p, end, &d)) return false;
            group_delta = static_cast<ElfW(Addr)>(d);
        }
        if (flags & kGroupedByInfo) {
            int64_t info_val = 0;
            if (!ReadSleb128(p, end, &info_val)) return false;
            r_info = static_cast<uint64_t>(info_val);
        }

        // Addend accumulator semantics (RELA), mirroring bionic exactly: a group
        // WITHOUT GROUP_HAS_ADDEND resets the running addend to 0 — not only when
        // it is also grouped-by-addend. Missing this reset leaks the previous
        // group's addend (e.g. a RELATIVE target) into the next group's
        // relocations, corrupting R_*_64/ABS and GLOB_DAT results.
        const bool has_addend = flags & kGroupHasAddend;
        if (!has_addend) {
            r_addend = 0;
        } else if (flags & kGroupedByAddend) {
            // Addend shared by the whole group: one delta, applied once.
            int64_t ad = 0;
            if (!ReadSleb128(p, end, &ad)) return false;
            r_addend += ad;
        }

        for (int64_t i = 0; i < group_size; i++) {
            if (flags & kGroupedByOffsetDelta) {
                r_offset += group_delta;
            } else {
                int64_t od = 0;
                if (!ReadSleb128(p, end, &od)) return false;
                r_offset += static_cast<ElfW(Addr)>(od);
            }
            if (!(flags & kGroupedByInfo)) {
                int64_t iv = 0;
                if (!ReadSleb128(p, end, &iv)) return false;
                r_info = static_cast<uint64_t>(iv);
            }
            if (has_addend && !(flags & kGroupedByAddend)) {
                int64_t ad = 0;
                if (!ReadSleb128(p, end, &ad)) return false;
                r_addend += ad;
            }
            emit(r_offset, r_info, r_addend);
        }
        idx += group_size;
    }
    return true;
}

// RELR: compact relative-only relocations. Even entries are addresses, odd
// entries are bitmaps of the following word-aligned slots.
void ForEachRelr(const ElfW(Relr) * table, size_t count, uintptr_t load_bias,
                 const std::function<void(ElfW(Addr) *)> &emit) {
    ElfW(Addr) *base = nullptr;
    for (size_t i = 0; i < count; i++) {
        ElfW(Relr) entry = table[i];
        if ((entry & 1) == 0) {
            base = reinterpret_cast<ElfW(Addr) *>(load_bias + entry);
            emit(base);
            base++;
            continue;
        }
        ElfW(Addr) *where = base;
        for (ElfW(Relr) bits = entry >> 1; bits != 0; bits >>= 1) {
            if (bits & 1) emit(where);
            where++;
        }
        base += (8 * sizeof(ElfW(Relr)) - 1);
    }
}

}  // namespace linker
