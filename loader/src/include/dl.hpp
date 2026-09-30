#pragma once

#include <dlfcn.h>

void *DlopenMem(int memfd, int flags, const char* name = nullptr);
