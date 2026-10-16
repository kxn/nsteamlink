cmake_minimum_required(VERSION 3.22)

project(nsteamlink
    VERSION 0.3.0
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

option(NSL_ADAPTIVE_PACING "Enable runtime adaptive video scheduling on deko" ON)
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

# The runtime uses SNS for cloud-only hosts, with SDK-selected ICE/SDR routes.
option(NSL_BUILD_SNS "Build the SNS media backend" ON)
if(NSL_BUILD_SNS)
    set(NSL_GNS_MBEDTLS_SOURCE "${CMAKE_SOURCE_DIR}/app/platforms/common/gns_mbedtls.cpp")
    if(NSL_PLATFORM STREQUAL "switch")
        set(USE_CRYPTO MbedTLS CACHE STRING "SNS crypto provider" FORCE)
        set(USE_CRYPTO25519 Reference CACHE STRING "SNS 25519 provider" FORCE)
        set(Protobuf_DIR "${CMAKE_SOURCE_DIR}/build/deps/sns-switch/lib/cmake/protobuf"
            CACHE PATH "Switch SNS protobuf runtime" FORCE)
        if(NOT EXISTS "${Protobuf_DIR}/protobuf-config.cmake")
            message(FATAL_ERROR "Run scripts/setup-sns-deps.sh to build the Switch SNS protobuf runtime")
        endif()
        find_program(NSL_HOST_PROTOC NAMES protoc
            HINTS "${CMAKE_SOURCE_DIR}/build/deps/sns-host/bin" NO_CMAKE_FIND_ROOT_PATH REQUIRED)
        set(Protobuf_PROTOC_EXECUTABLE "${NSL_HOST_PROTOC}" CACHE FILEPATH "Host SNS protoc" FORCE)
    endif()
    set(BUILD_STATIC_LIB ON CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
    set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(BUILD_TOOLS OFF CACHE BOOL "" FORCE)
    set(ENABLE_ICE ON CACHE BOOL "" FORCE)
    set(USE_STEAMWEBRTC OFF CACHE BOOL "" FORCE)
    option(NSL_ENABLE_SDR "Enable the reconstructed Valve relay transport" ON)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(NSL_GNS_SOURCE "${CMAKE_BINARY_DIR}/dependencies/GameNetworkingSockets")
    execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/cmake/prepare-gns.py"
        "${CMAKE_SOURCE_DIR}/third_party/GameNetworkingSockets" "${NSL_GNS_SOURCE}"
        "${CMAKE_SOURCE_DIR}/third_party/patches/GameNetworkingSockets"
        COMMAND_ERROR_IS_FATAL ANY)
    add_subdirectory("${NSL_GNS_SOURCE}" third_party/GameNetworkingSockets)
    if(NSL_PLATFORM STREQUAL "switch")
        target_compile_definitions(GameNetworkingSockets_s PRIVATE VALVE_POSIX=1 PLATFORM_ARM=1
            STEAMNETWORKINGSOCKETS_DISABLE_STEAMNETWORKINGMESSAGES)
        target_sources(GameNetworkingSockets_s PRIVATE app/platforms/switch/gns_libnx.cpp)
    endif()
    if(NSL_ENABLE_SDR)
        target_compile_definitions(GameNetworkingSockets_s PRIVATE NSL_GNS_SDR=1)
    endif()
endif()

enable_testing()
add_subdirectory(app)

if(NSL_PLATFORM STREQUAL "switch" AND NSL_BUILD_TOOLS)
    add_subdirectory(tools/switch-discover)
    add_subdirectory(client)
endif()

if(NSL_PLATFORM STREQUAL "desktop")
    add_subdirectory(third_party/ihslib/tests)
endif()
