project(external)

option(LSPLT_BUILD_SHARED OFF)
add_subdirectory(lsplt/lsplt/src/main/jni)

if(NOT ANDROID_ABI STREQUAL "riscv64")
    add_subdirectory(bhook)
    include(yukiplt/cmake/YukiPLTSources.cmake)
    add_library(yukiplt_static STATIC ${YUKIPLT_SOURCES})
    target_compile_definitions(yukiplt_static PUBLIC YUKIPLT_STATIC=1)
    target_include_directories(yukiplt_static
        PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/yukiplt/include"
        PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/yukiplt/src")
    target_compile_options(yukiplt_static PRIVATE
        -fexceptions -funwind-tables -fasynchronous-unwind-tables
        -fvisibility=hidden -fvisibility-inlines-hidden
        -Wno-unused-parameter)
    target_link_libraries(yukiplt_static PRIVATE dl)
endif()

# Dobby has no riscv64 backend; inline hook is unavailable there.
if(NOT ANDROID_ABI STREQUAL "riscv64")
    option(DOBBY_BUILD_SHARED OFF)
    option(DOBBY_GENERATE_SHARED OFF)
    add_subdirectory(dobby)
else()
    add_subdirectory(rv64hook)
endif()

add_subdirectory(lzma)
