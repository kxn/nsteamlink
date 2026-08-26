find_package(PkgConfig REQUIRED)
pkg_check_modules(FFMPEG REQUIRED IMPORTED_TARGET libavcodec libavutil libswscale)
pkg_check_modules(SDL2 REQUIRED IMPORTED_TARGET sdl2)

# M3 probe: request a Steam stream and verify session/video channel without decoding.
add_executable(switch-stream-probe main.c media.c)
target_include_directories(switch-stream-probe PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf
    $ENV{DEVKITPRO}/portlibs/switch/include)
target_compile_options(switch-stream-probe PRIVATE -g)
target_link_options(switch-stream-probe PRIVATE -g)
target_link_libraries(switch-stream-probe PRIVATE ihslib PkgConfig::FFMPEG PkgConfig::SDL2 nx)
nx_create_nro(switch-stream-probe OUTPUT switch-stream-probe.nro)

# Core-only probe: same auth/discovery/debug/exit path, no SDL/FFmpeg link.
# Use this to separate hbloader/netloader startup stability from media-library startup.
add_executable(switch-stream-probe-core main.c media_stub.c)
target_include_directories(switch-stream-probe-core PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf
    $ENV{DEVKITPRO}/portlibs/switch/include)
target_compile_options(switch-stream-probe-core PRIVATE -g)
target_link_options(switch-stream-probe-core PRIVATE -g)
target_link_libraries(switch-stream-probe-core PRIVATE ihslib nx)
nx_create_nro(switch-stream-probe-core OUTPUT switch-stream-probe-core.nro)
