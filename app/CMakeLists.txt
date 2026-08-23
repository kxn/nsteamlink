set(NSL_SOURCES src/main.c)

if(NSL_PLATFORM STREQUAL "switch")
    list(APPEND NSL_SOURCES platforms/switch/hal.c)
else()
    list(APPEND NSL_SOURCES platforms/desktop/hal.c)
endif()

add_executable(nsteamlink ${NSL_SOURCES})
target_include_directories(nsteamlink PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

if(NSL_PLATFORM STREQUAL "switch")
    # 需要 $DEVKITPRO/tools/bin 下的 nacptool 与 elf2nro（switch-tools 包）
    nx_create_nro(nsteamlink OUTPUT nsteamlink.nro)
endif()
