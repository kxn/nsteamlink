find_package(PkgConfig REQUIRED)
pkg_check_modules(FFMPEG REQUIRED IMPORTED_TARGET libavcodec libavutil libswscale)
pkg_check_modules(SDL2 REQUIRED IMPORTED_TARGET sdl2)

# Streaming self-test: run a real Steam stream, verify session/video/decode and exit cleanly.
add_executable(switch-stream-selftest main.c media.c)
target_include_directories(switch-stream-selftest PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf
    $ENV{DEVKITPRO}/portlibs/switch/include)
target_compile_options(switch-stream-selftest PRIVATE -g)
target_link_options(switch-stream-selftest PRIVATE -g)
target_link_libraries(switch-stream-selftest PRIVATE ihslib PkgConfig::FFMPEG PkgConfig::SDL2 nx)
nx_create_nro(switch-stream-selftest OUTPUT switch-stream-selftest.nro)

# Core-only self-test: same auth/discovery/debug/exit path, no SDL/FFmpeg link.
# Use this to separate hbloader/netloader startup stability from media-library startup.
add_executable(switch-stream-selftest-core main.c media_stub.c)
target_include_directories(switch-stream-selftest-core PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf
    $ENV{DEVKITPRO}/portlibs/switch/include)
target_compile_options(switch-stream-selftest-core PRIVATE -g)
target_link_options(switch-stream-selftest-core PRIVATE -g)
target_link_libraries(switch-stream-selftest-core PRIVATE ihslib nx)
nx_create_nro(switch-stream-selftest-core OUTPUT switch-stream-selftest-core.nro)
