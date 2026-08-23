cmake_minimum_required(VERSION 3.22)

project(nsteamlink
    VERSION 0.1.0
    DESCRIPTION "Steam Remote Play client for Nintendo Switch"
    LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# devkitPro 的 Switch.cmake 工具链会把 CMAKE_SYSTEM_NAME 置为 NintendoSwitch
if(CMAKE_SYSTEM_NAME STREQUAL "NintendoSwitch")
    set(NSL_PLATFORM "switch")
else()
    set(NSL_PLATFORM "desktop")
endif()
message(STATUS "nsteamlink target platform: ${NSL_PLATFORM}")

add_subdirectory(app)
