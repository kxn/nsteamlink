# Android client's embedded decoder identifies as unknown-fixed; §72 records
# the original-code PCM comparison and the floating/fixed counterexample.
# This dependency pin does not identify Steam's unknown codec version.
include(FetchContent)
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()
FetchContent_Declare(nsl_opus
    URL https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz
    URL_HASH SHA256=65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1)

function(nsl_add_opus)
    # Scope upstream generic flags to this dependency, preserving project tests.
    set(BUILD_SHARED_LIBS OFF)
    set(BUILD_TESTING OFF)
    set(OPUS_FIXED_POINT ON CACHE BOOL "Match official client fixed-point codec" FORCE)
    set(OPUS_ENABLE_FLOAT_API ON CACHE BOOL "Official decoder output API" FORCE)
    set(OPUS_BUILD_SHARED_LIBRARY OFF CACHE BOOL "Embed codec in the client" FORCE)
    set(OPUS_BUILD_TESTING OFF CACHE BOOL "Do not build upstream codec tests" FORCE)
    set(OPUS_BUILD_PROGRAMS OFF CACHE BOOL "Do not build upstream codec tools" FORCE)
    set(OPUS_INSTALL_PKG_CONFIG_MODULE OFF CACHE BOOL "No global codec installation" FORCE)
    set(OPUS_INSTALL_CMAKE_CONFIG_MODULE OFF CACHE BOOL "No global codec installation" FORCE)
    set(OPUS_DRED OFF CACHE BOOL "No unverified alternative recovery mode" FORCE)
    set(OPUS_OSCE OFF CACHE BOOL "Use the audited decoder path" FORCE)
    # Upstream 1.5.2 CMake unconditionally adds a float-only encoder AVX2
    # source without its headers in fixed builds. Its SSE fixed kernels work.
    set(OPUS_X86_MAY_HAVE_AVX2 OFF CACHE BOOL "Avoid fixed-build upstream AVX2 source mismatch" FORCE)
    if(NSL_PLATFORM STREQUAL "switch")
        set(OPUS_MAY_HAVE_NEON OFF CACHE BOOL "Single known Switch CPU" FORCE)
        set(OPUS_PRESUME_NEON ON CACHE BOOL "Switch AArch64 NEON" FORCE)
    endif()
    FetchContent_MakeAvailable(nsl_opus)
endfunction()
nsl_add_opus()
