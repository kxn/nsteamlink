cmake_minimum_required(VERSION 3.22)

project(nsteamlink
    VERSION 0.1.1
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

option(NSL_DIAGNOSTICS "Compile advanced diagnostics, UDP console and log collection" OFF)
option(NSL_BUILD_TOOLS "Build standalone Switch diagnostic tools" ${NSL_DIAGNOSTICS})
set(NSL_IDENTITY_DIR "${CMAKE_BINARY_DIR}/generated")
execute_process(COMMAND "${CMAKE_COMMAND}" -DSOURCE_DIR=${CMAKE_SOURCE_DIR}
    -DOUTPUT_DIR=${NSL_IDENTITY_DIR} -DAPP_VERSION=${PROJECT_VERSION}
    -P "${CMAKE_SOURCE_DIR}/cmake/BuildIdentity.cmake" COMMAND_ERROR_IS_FATAL ANY)
add_custom_target(nsl_identity ALL
    COMMAND "${CMAKE_COMMAND}" -DSOURCE_DIR=${CMAKE_SOURCE_DIR}
        -DOUTPUT_DIR=${NSL_IDENTITY_DIR} -DAPP_VERSION=${PROJECT_VERSION}
        -P "${CMAKE_SOURCE_DIR}/cmake/BuildIdentity.cmake"
    BYPRODUCTS "${NSL_IDENTITY_DIR}/build_identity.h" "${NSL_IDENTITY_DIR}/build_identity.json"
    VERBATIM)

set(IHSLIB_HID_SDL ON CACHE BOOL "Build ihslib SDL HID provider" FORCE)
set(IHSLIB_HID_SDL_USE_SDL2 ON CACHE BOOL "Build ihslib SDL HID provider against SDL2" FORCE)
add_subdirectory(third_party/ihslib)

enable_testing()
add_subdirectory(app)

if(NSL_PLATFORM STREQUAL "switch" AND NSL_BUILD_TOOLS)
    add_subdirectory(tools/switch-discover)
    add_subdirectory(client)
endif()

if(NSL_PLATFORM STREQUAL "desktop")
    add_subdirectory(third_party/ihslib/tests)
endif()
