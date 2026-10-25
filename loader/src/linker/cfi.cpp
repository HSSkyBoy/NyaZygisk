#include "cfi.hpp"

namespace linker {

int CfiMarkUncheckedRange(uintptr_t shadow_start, uintptr_t shadow_end, uintptr_t base,
                          size_t size) {
    if (size == 0) return 0;

    uintptr_t end = base + size - 1;
    uintptr_t dst = shadow_start + CfiShadowByteOffset(base);
    uintptr_t dst_end = shadow_start + CfiShadowByteOffset(end) + sizeof(uint16_t);
    if (dst < shadow_start || dst_end > shadow_end || dst_end <= dst) return 0;

    int changed = 0;
    for (uintptr_t p = dst; p < dst_end; p += sizeof(uint16_t)) {
        auto *slot = reinterpret_cast<uint16_t *>(p);
        if (*slot == kCfiInvalidShadow) {
            *slot = kCfiUncheckedShadow;
            ++changed;
        }
    }
    return changed;
}

}  // namespace linker
