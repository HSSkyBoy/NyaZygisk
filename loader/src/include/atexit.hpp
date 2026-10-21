#pragma once

#include <inttypes.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/cdefs.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/user.h>

#include <memory>
#include <string>

namespace Atexit {

inline size_t page_size() {
#if defined(PAGE_SIZE)
    return PAGE_SIZE;
#else
    static const size_t page_size = getauxval(AT_PAGESZ);
    return page_size;
#endif
}

// The maximum page size supported on any Android device. As
// of API level 35, this is limited by ART.
constexpr size_t max_android_page_size() {
#if defined(PAGE_SIZE)
    return PAGE_SIZE;
#else
    return 16384;
#endif
}

// Returns the address of the page containing address 'x'.
inline uintptr_t page_start(uintptr_t x) { return x & ~(page_size() - 1); }

// Returns the offset of address 'x' in its page.
inline uintptr_t page_offset(uintptr_t x) { return x & (page_size() - 1); }

// Returns the address of the next page after address 'x', unless 'x' is
// itself at the start of a page.
inline uintptr_t page_end(uintptr_t x) { return page_start(x + page_size() - 1); }

struct AtexitEntry {
    void (*fn)(void*);  // the __cxa_atexit callback
    void* arg;          // argument for `fn` callback
    void* dso;          // shared module handle
};

class AtexitArray {
public:
    AtexitArray(AtexitEntry* existing_array, size_t current_size, size_t current_capacity,
                size_t initial_extracted_count, uint64_t initial_total_appends)
        : array_(existing_array),
          size_(current_size),
          extracted_count_(initial_extracted_count),
          capacity_(current_capacity),
          total_appends_(initial_total_appends) {}

    std::string format_state_string() const {
        char buf[640];
        snprintf(buf, sizeof(buf),
                 "\n--- Live AtexitArray Snapshot State ---\n"
                 "\t(this pointer):  %p\n"
                 "\tarray_:          %p\n"
                 "\tsize_:           %zu (0x%zx)\n"
                 "\textracted_count_: %zu (0x%zx)\n"
                 "\tcapacity_:       %zu (0x%zx)\n"
                 "\ttotal_appends_:  %" PRIu64 " (0x%" PRIx64 ")\n"
                 "---------------------------------------",
                 static_cast<const void*>(this), static_cast<const void*>(array_), size_, size_,
                 extracted_count_, extracted_count_, capacity_, capacity_, total_appends_,
                 total_appends_);
        return buf;
    }

    size_t size() const { return size_; }
    uint64_t total_appends() const { return total_appends_; }
    const AtexitEntry& operator[](size_t idx) const { return array_[idx]; }
    bool isSane() const {
        constexpr size_t MAX_REASONABLE_ATEXIT_ENTRIES = 4096 * 16;
        return array_ != nullptr && size_ <= capacity_ && capacity_ < MAX_REASONABLE_ATEXIT_ENTRIES &&
               extracted_count_ <= size_;
    }

    void recompact();

private:
    AtexitEntry* array_;
    size_t size_;
    size_t extracted_count_;
    size_t capacity_;

    // An entry can be appended by a __cxa_finalize callback. Track the number of appends so we
    // restart concurrent __cxa_finalize passes.
    uint64_t total_appends_;

    static size_t page_start_of_index(size_t idx) { return page_start(idx * sizeof(AtexitEntry)); }
    static size_t page_end_of_index(size_t idx) { return page_end(idx * sizeof(AtexitEntry)); }

    // Recompact the array if it will save at least one page of memory at the end.
    bool needs_recompaction() const {
        return page_end_of_index(size_ - extracted_count_) < page_end_of_index(size_);
    }

    bool set_writable(bool writable, size_t start_idx, size_t num_entries);
};

AtexitArray* findAtexitArray();

}  // namespace Atexit
