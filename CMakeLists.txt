cmake_minimum_required(VERSION 3.22)

project(nsteamlink
    VERSION 0.1.0
    DESCRIPTION "Steam Remote Play client for Nintendo Switch"
    LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# devkitPro 的 Switch.cmake 工具链会把 CMAKE_SYSTEM_NAME 置为 NintendoSwitch
if(CMAKE_SYSTEM_NAME STREQUAL "NintendoSwitch")
    set(NSL_PLATFORM "switch")
    # 自定义系统名不会自动置 UNIX；ihslib 平台层靠它选 POSIX 后端（decisions D-002/D-007）
    set(UNIX ON)
else()
    set(NSL_PLATFORM "desktop")
endif()
message(STATUS "nsteamlink target platform: ${NSL_PLATFORM}")

if(NSL_PLATFORM STREQUAL "switch")
    set(IHSLIB_HID_SDL ON CACHE BOOL "Build ihslib SDL HID provider" FORCE)
    set(IHSLIB_HID_SDL_USE_SDL2 ON CACHE BOOL "Build ihslib SDL HID provider against SDL2" FORCE)
    add_subdirectory(third_party/ihslib)
endif()

add_subdirectory(app)

if(NSL_PLATFORM STREQUAL "switch")
    add_subdirectory(tools/switch-discover)
    add_subdirectory(client)
    add_subdirectory(tools/switch-gfx-probe)
endif()
