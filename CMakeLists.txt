cmake_minimum_required(VERSION 3.18)

project(bsdiff)

include(CTest)

option(BUILD_SHARED_LIBS "Set to ON to build shared libraries" OFF)
option(BUILD_STANDALONES "Set to OFF to not build standalones" ON)
option(USE_SYSTEM_BZIP2 "Set to ON to use system bzip2" OFF)

if (USE_SYSTEM_BZIP2)
    find_package(BZip2 REQUIRED)
else()
# bzip2
    add_library(bzip2 STATIC
        3rdparty/bzip2/bzlib.c
        3rdparty/bzip2/compress.c
        3rdparty/bzip2/decompress.c
        3rdparty/bzip2/blocksort.c
        3rdparty/bzip2/crctable.c
        3rdparty/bzip2/huffman.c
        3rdparty/bzip2/randtable.c)
    target_include_directories(bzip2 PUBLIC 3rdparty/bzip2)
    add_library(BZip2::BZip2 ALIAS bzip2)
endif()

set(ZLIB_USE_STATIC_LIBS ON)
find_package(ZLIB REQUIRED)
find_package(zstd CONFIG REQUIRED)

# libdivsufsort
function(add_libdivsufsort)
    set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
    set(BUILD_EXAMPLES OFF)
    set(BUILD_DIVSUFSORT64 ON)
    set(BUILD_SHARED_LIBS OFF)
    add_subdirectory(3rdparty/libdivsufsort)
endfunction()

add_libdivsufsort()

# bsdiff
add_library(bsdiff
    source/bsdiff_private.h
    source/misc.c
    source/stream_file.c
    source/stream_memory.c
    source/stream_sub.c
    source/compressor_bz2.c
    source/decompressor_bz2.c
    source/decompressor_zlib.c
    source/decompressor_zstd.c
    source/decompressor_dummy.c
    source/patch_packer_maa.c
    source/bsdiff.c
    source/bspatch.c)
target_include_directories(bsdiff
    PRIVATE "3rdparty/bzip2"
    PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/3rdparty/libdivsufsort/include"
    PRIVATE "include")
if (BUILD_SHARED_LIBS)
    target_compile_definitions(bsdiff PRIVATE "BSDIFF_DLL" "BSDIFF_EXPORTS")
endif()
if (MSVC)
    target_compile_definitions(bsdiff PRIVATE "_CRT_SECURE_NO_WARNINGS")
endif()
target_link_libraries(bsdiff PRIVATE divsufsort divsufsort64 BZip2::BZip2 ZLIB::ZLIB zstd::libzstd_static)

if (BUILD_STANDALONES)
    # bsdiff_app
    add_executable(bsdiff_app source/bsdiff_app.c)
    set_target_properties(bsdiff_app PROPERTIES OUTPUT_NAME "bsdiff")
    target_include_directories(bsdiff_app PRIVATE "include")
    if (BUILD_SHARED_LIBS)
        target_compile_definitions(bsdiff_app PRIVATE "BSDIFF_DLL")
    endif()
    target_link_libraries(bsdiff_app PRIVATE bsdiff)

    # bspatch_app
    add_executable(bspatch_app source/bspatch_app.c)
    set_target_properties(bspatch_app PROPERTIES OUTPUT_NAME "bspatch")
    target_include_directories(bspatch_app PRIVATE "include")
    if (BUILD_SHARED_LIBS)
        target_compile_definitions(bspatch_app PRIVATE "BSDIFF_DLL")
    endif()
    target_link_libraries(bspatch_app PRIVATE bsdiff)
endif()

if (BUILD_TESTING)
    add_subdirectory(testdata)
endif()
