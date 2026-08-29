cmake_minimum_required(VERSION 3.10)
project(lzma C)

add_library(lzma STATIC LzmaDec.c)
target_include_directories(lzma PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(lzma PRIVATE -Wno-unused -Wno-sign-compare)
