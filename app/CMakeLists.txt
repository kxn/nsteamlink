set(NSL_SOURCES src/main.c)

if(NSL_PLATFORM STREQUAL "switch")
    list(APPEND NSL_SOURCES platforms/switch/hal.c)
    find_package(PkgConfig REQUIRED)
    if(NOT TARGET PkgConfig::FFMPEG)
        pkg_check_modules(FFMPEG REQUIRED IMPORTED_TARGET libavcodec libavutil libswscale)
    endif()
    if(NOT TARGET PkgConfig::SDL2)
        pkg_check_modules(SDL2 REQUIRED IMPORTED_TARGET sdl2)
    endif()

    set(NSL_CLIENT_MAIN ${CMAKE_SOURCE_DIR}/client/main.c)
    set(NSL_CLIENT_MEDIA ${CMAKE_SOURCE_DIR}/client/media.c)
    set_source_files_properties(${NSL_CLIENT_MAIN}
        PROPERTIES COMPILE_DEFINITIONS "main=nsteamlink_stream_main;NSTREAMLINK_APP=1")
    set_source_files_properties(${NSL_CLIENT_MEDIA}
        PROPERTIES COMPILE_DEFINITIONS "NSTREAMLINK_APP=1")
    list(APPEND NSL_SOURCES
        ${NSL_CLIENT_MAIN}
        ${NSL_CLIENT_MEDIA})
else()
    list(APPEND NSL_SOURCES platforms/desktop/hal.c)
endif()

add_executable(nsteamlink ${NSL_SOURCES})
target_include_directories(nsteamlink PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

if(NSL_PLATFORM STREQUAL "switch")
    target_include_directories(nsteamlink PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf
        $ENV{DEVKITPRO}/portlibs/switch/include)
    target_compile_options(nsteamlink PRIVATE -g)
    target_link_options(nsteamlink PRIVATE -g)
    target_link_libraries(nsteamlink PRIVATE ihslib ihslib-hid-sdl PkgConfig::FFMPEG PkgConfig::SDL2 nx)
    # 需要 $DEVKITPRO/tools/bin 下的 nacptool 与 elf2nro（switch-tools 包）
    nx_create_nro(nsteamlink OUTPUT nsteamlink.nro)
endif()
