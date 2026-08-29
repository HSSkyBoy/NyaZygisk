project(external)

option(LSPLT_BUILD_SHARED OFF)
add_subdirectory(lsplt/lsplt/src/main/jni)

option(DOBBY_BUILD_SHARED OFF)
option(DOBBY_GENERATE_SHARED OFF)
add_subdirectory(dobby)

add_subdirectory(lzma)
