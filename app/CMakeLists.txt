find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(NSL_I18N_DIR "${CMAKE_CURRENT_BINARY_DIR}/i18n")
add_custom_command(OUTPUT "${NSL_I18N_DIR}/i18n_keys.h" "${NSL_I18N_DIR}/i18n_data.h"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/scripts/compile-i18n.py"
        "${CMAKE_CURRENT_SOURCE_DIR}/resources/i18n" "${NSL_I18N_DIR}"
    DEPENDS "${CMAKE_SOURCE_DIR}/scripts/compile-i18n.py"
        resources/i18n/zh-CN.json resources/i18n/en.json VERBATIM)
add_custom_target(nsl_i18n DEPENDS "${NSL_I18N_DIR}/i18n_keys.h" "${NSL_I18N_DIR}/i18n_data.h")
find_package(PkgConfig REQUIRED)
pkg_check_modules(SDL2 REQUIRED IMPORTED_TARGET sdl2)
pkg_check_modules(SDL2_TTF REQUIRED IMPORTED_TARGET SDL2_ttf)
pkg_check_modules(FFMPEG REQUIRED IMPORTED_TARGET libavcodec libavutil libswscale)
pkg_check_modules(OPUS REQUIRED IMPORTED_TARGET opus)
pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)
pkg_check_modules(JPEG REQUIRED IMPORTED_TARGET libjpeg)
find_package(Threads REQUIRED)
add_library(nsl_sdr_core STATIC platforms/common/sdr_wire.c platforms/common/sdr_config.c
    platforms/common/sdr_policy.c)
target_include_directories(nsl_sdr_core PUBLIC platforms/common PRIVATE ${CMAKE_SOURCE_DIR}/third_party/jsmn)
target_compile_options(nsl_sdr_core PRIVATE -Wall -Wextra)
add_library(nsl_remote STATIC platforms/common/remote_wire.c platforms/common/remote_protocol.c
    platforms/common/remote_connection.c platforms/common/stream_bridge.c)
target_include_directories(nsl_remote PUBLIC platforms/common PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/jsmn ${CMAKE_SOURCE_DIR}/third_party/ihslib/src
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client)
target_include_directories(nsl_remote SYSTEM PRIVATE ${MBEDTLS_INCLUDE_DIRS})
target_compile_options(nsl_remote PRIVATE -Wall -Wextra)
target_compile_definitions(nsl_remote PRIVATE NSL_DIAGNOSTICS=$<BOOL:${NSL_DIAGNOSTICS}>)
target_link_libraries(nsl_remote PUBLIC ihslib nsl_sdr_core PkgConfig::CURL ${MBEDCRYPTO_LIBRARY})
if(NSL_BUILD_SNS)
    target_compile_definitions(GameNetworkingSockets_s PRIVATE NSL_SNS_PROBES=$<BOOL:${NSL_BUILD_TOOLS}>)
    target_sources(GameNetworkingSockets_s PRIVATE platforms/common/gns_hooks.cpp)
    set(NSL_SDR_PROTO_DIR "${CMAKE_CURRENT_BINARY_DIR}/sdr-protobuf")
    find_program(NSL_HOST_PROTOC NAMES protoc NO_CMAKE_FIND_ROOT_PATH REQUIRED)
    file(MAKE_DIRECTORY "${NSL_SDR_PROTO_DIR}")
    add_custom_command(OUTPUT "${NSL_SDR_PROTO_DIR}/steamdatagram_messages_sdr.pb.cc"
        "${NSL_SDR_PROTO_DIR}/steamdatagram_messages_sdr.pb.h"
        COMMAND "${NSL_HOST_PROTOC}" --cpp_out=${NSL_SDR_PROTO_DIR}
            -I${CMAKE_SOURCE_DIR}/third_party/GameNetworkingSockets/src/common
            -I${CMAKE_SOURCE_DIR}/docs/protocol/steamlink-1.3.32
            ${CMAKE_SOURCE_DIR}/docs/protocol/steamlink-1.3.32/steamdatagram_messages_sdr.proto
        DEPENDS ${CMAKE_SOURCE_DIR}/docs/protocol/steamlink-1.3.32/steamdatagram_messages_sdr.proto
        VERBATIM)
    add_custom_target(nsl_sdr_proto DEPENDS "${NSL_SDR_PROTO_DIR}/steamdatagram_messages_sdr.pb.cc"
        "${NSL_SDR_PROTO_DIR}/steamdatagram_messages_sdr.pb.h")
    add_dependencies(GameNetworkingSockets_s nsl_sdr_proto)
    set_source_files_properties("${NSL_SDR_PROTO_DIR}/steamdatagram_messages_sdr.pb.cc"
        TARGET_DIRECTORY GameNetworkingSockets_s PROPERTIES GENERATED TRUE)
    target_sources(GameNetworkingSockets_s PRIVATE platforms/common/sdr_probe.cpp
        "${NSL_SDR_PROTO_DIR}/steamdatagram_messages_sdr.pb.cc")
    target_include_directories(GameNetworkingSockets_s PRIVATE ${CMAKE_SOURCE_DIR}/third_party/jsmn
        ${NSL_GNS_SOURCE}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/platforms/common ${NSL_SDR_PROTO_DIR})
    target_link_libraries(GameNetworkingSockets_s PRIVATE "$<BUILD_INTERFACE:nsl_sdr_core>")
    add_library(nsl_sns STATIC platforms/common/sns_backend.cpp)
    target_compile_features(nsl_sns PRIVATE cxx_std_17)
    target_compile_definitions(nsl_sns PRIVATE NSL_ENABLE_SDR=$<BOOL:${NSL_ENABLE_SDR}>)
    target_compile_definitions(nsl_sns PUBLIC NSL_SNS_PROBES=$<BOOL:${NSL_BUILD_TOOLS}>)
    target_compile_options(nsl_sns PRIVATE -Wall -Wextra)
    target_include_directories(nsl_sns PUBLIC platforms/common)
    target_link_libraries(nsl_sns PUBLIC nsl_remote GameNetworkingSockets::GameNetworkingSockets_s
        Threads::Threads)
endif()
add_library(nsl_video_contracts STATIC platforms/common/frame_lifetime.c platforms/common/app_lifecycle.c)
target_include_directories(nsl_video_contracts PUBLIC platforms/common)
target_compile_options(nsl_video_contracts PRIVATE -Wall -Wextra)
add_library(nsl_video_pipeline STATIC platforms/common/video_pipeline.c)
target_compile_definitions(nsl_video_pipeline PRIVATE NSL_DIAGNOSTICS=$<BOOL:${NSL_DIAGNOSTICS}>)
target_include_directories(nsl_video_pipeline PUBLIC platforms/common)
target_compile_options(nsl_video_pipeline PRIVATE -Wall -Wextra -Wno-unknown-pragmas)
target_link_libraries(nsl_video_pipeline PUBLIC nsl_video_contracts ihslib PkgConfig::FFMPEG Threads::Threads)
# Backend is a platform property, not a selectable Switch fallback. Clear old
# caches so an existing SDL Switch build directory also migrates to deko.
unset(NSL_GFX_BACKEND CACHE)
if(NSL_PLATFORM STREQUAL "switch")
    if(NSL_BUILD_TOOLS AND NSL_BUILD_SNS)
        add_executable(nsl-sns-switch-probe tests/switch_sns_probe.cpp)
        target_compile_features(nsl-sns-switch-probe PRIVATE cxx_std_17)
        target_link_libraries(nsl-sns-switch-probe PRIVATE GameNetworkingSockets::GameNetworkingSockets_s nx)
        nx_generate_nacp("${CMAKE_CURRENT_BINARY_DIR}/sns-probe.nacp"
            NAME "SNS transport probe" AUTHOR "nsteamlink" VERSION "1")
        nx_create_nro(nsl-sns-switch-probe OUTPUT nsl-sns-switch-probe.nro
            NACP "${CMAKE_CURRENT_BINARY_DIR}/sns-probe.nacp")
    endif()
    set(NSL_GFX_BACKEND "deko")
else()
    set(NSL_GFX_BACKEND "sdl")
endif()
add_library(nsl_gfx STATIC platforms/common/gfx_common.c platforms/common/frame_pacer.c platforms/common/video_scheduler.c)
target_compile_definitions(nsl_gfx PUBLIC NSL_DIAGNOSTICS=$<BOOL:${NSL_DIAGNOSTICS}>)
if(NSL_PLATFORM STREQUAL "switch")
    find_program(NSL_UAM uam HINTS /opt/devkitpro/tools/bin NO_CMAKE_FIND_ROOT_PATH REQUIRED)
    if(NSL_DIAGNOSTICS)
        find_library(NSL_DEKO3D_DEBUG deko3dd REQUIRED)
        set(NSL_DEKO3D "${NSL_DEKO3D_DEBUG}")
    else()
        find_library(NSL_DEKO3D_RELEASE deko3d REQUIRED)
        set(NSL_DEKO3D "${NSL_DEKO3D_RELEASE}")
    endif()
    target_sources(nsl_gfx PRIVATE platforms/switch/gfx.c platforms/switch/video_surface.c)
    target_link_libraries(nsl_gfx PUBLIC ${NSL_DEKO3D})
    target_compile_definitions(nsl_gfx PUBLIC NSL_GFX_DEKO=1)
    foreach(stage vert frag)
        set(shader "${CMAKE_CURRENT_BINARY_DIR}/quad_${stage}.dksh")
        set(embedded "${CMAKE_CURRENT_BINARY_DIR}/quad_${stage}.c")
        add_custom_command(OUTPUT "${shader}"
            COMMAND "${NSL_UAM}" -s ${stage} -o "${shader}"
                "${CMAKE_CURRENT_SOURCE_DIR}/platforms/switch/shaders/quad.${stage}"
            DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/platforms/switch/shaders/quad.${stage}" "${NSL_UAM}" VERBATIM)
        add_custom_command(OUTPUT "${embedded}"
            COMMAND "${CMAKE_COMMAND}" -DINPUT=${shader} -DOUTPUT=${embedded}
                -DSYMBOL=nsl_quad_${stage} -P "${CMAKE_SOURCE_DIR}/cmake/EmbedAsset.cmake"
            DEPENDS "${shader}" "${CMAKE_SOURCE_DIR}/cmake/EmbedAsset.cmake" VERBATIM)
        target_sources(nsl_gfx PRIVATE "${embedded}")
    endforeach()
else()
    target_sources(nsl_gfx PRIVATE platforms/desktop/gfx.c)
    target_compile_definitions(nsl_gfx PUBLIC NSL_GFX_DEKO=0)
endif()
target_include_directories(nsl_gfx PUBLIC src PRIVATE platforms/common)
target_link_libraries(nsl_gfx PUBLIC nsl_video_pipeline PkgConfig::SDL2)
target_compile_options(nsl_gfx PRIVATE -Wall -Wextra -Wno-unknown-pragmas)
add_library(nsl_artwork STATIC platforms/common/artwork.c platforms/common/artwork_format.c)
target_include_directories(nsl_artwork PRIVATE ${CMAKE_SOURCE_DIR}/third_party/jsmn)
target_compile_options(nsl_artwork PRIVATE -Wall -Wextra)
target_link_libraries(nsl_artwork PUBLIC nsl_ui PkgConfig::CURL PkgConfig::JPEG Threads::Threads m)
# Self-update (D-055). mbedTLS comes from IHSlib's cached find results.
add_library(nsl_updater STATIC platforms/common/updater.c platforms/common/update_format.c)
target_include_directories(nsl_updater PUBLIC platforms/common
    PRIVATE ${CMAKE_SOURCE_DIR}/third_party/jsmn SYSTEM ${MBEDTLS_INCLUDE_DIRS})
target_compile_options(nsl_updater PRIVATE -Wall -Wextra)
target_link_libraries(nsl_updater PUBLIC nsl_ui PkgConfig::CURL ${MBEDCRYPTO_LIBRARY} Threads::Threads)
add_library(nsl_ui STATIC src/ui/ui_model.c src/ui/ui_layout.c src/ui/ui_events.c src/input/input_router.c
    src/services/host_registry.c src/services/auth_store.c src/services/i18n.c
    src/services/update_config.c)
target_include_directories(nsl_ui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(nsl_ui PRIVATE -Wall -Wextra)
target_link_libraries(nsl_ui PUBLIC m)
add_dependencies(nsl_ui nsl_identity nsl_i18n)
target_include_directories(nsl_ui PUBLIC ${NSL_IDENTITY_DIR} ${NSL_I18N_DIR})
target_compile_definitions(nsl_ui PUBLIC NSL_DIAGNOSTICS=$<BOOL:${NSL_DIAGNOSTICS}> NSL_ADAPTIVE_PACING=$<BOOL:${NSL_ADAPTIVE_PACING}>)
add_library(nsl_platform STATIC platforms/common/application.c platforms/common/sdl_input.c platforms/common/media.c
    platforms/common/shortcut_package.c platforms/${NSL_PLATFORM}/shortcut.c
    platforms/common/ui_renderer.c platforms/common/ui_audio.c platforms/common/runtime.c
    platforms/common/diagnostic_log.c platforms/${NSL_PLATFORM}/system.c
    platforms/${NSL_PLATFORM}/events.c)
target_include_directories(nsl_platform PRIVATE ${CMAKE_SOURCE_DIR}/third_party/ihslib/src
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf)
target_compile_options(nsl_platform PRIVATE -Wall -Wextra -Wno-unknown-pragmas)
add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/background.c"
    COMMAND "${CMAKE_COMMAND}" -DINPUT=${CMAKE_SOURCE_DIR}/assets/branding/background.bmp
        -DOUTPUT=${CMAKE_CURRENT_BINARY_DIR}/background.c -P ${CMAKE_SOURCE_DIR}/cmake/EmbedAsset.cmake
    DEPENDS ${CMAKE_SOURCE_DIR}/assets/branding/background.bmp ${CMAKE_SOURCE_DIR}/cmake/EmbedAsset.cmake
    VERBATIM)
target_sources(nsl_platform PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/background.c")
add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/connection_icons.c"
    COMMAND "${CMAKE_COMMAND}" -DINPUT=${CMAKE_SOURCE_DIR}/assets/ui/connection-icons.alpha
        -DOUTPUT=${CMAKE_CURRENT_BINARY_DIR}/connection_icons.c -DSYMBOL=nsl_connection_icons
        -P ${CMAKE_SOURCE_DIR}/cmake/EmbedAsset.cmake
    DEPENDS ${CMAKE_SOURCE_DIR}/assets/ui/connection-icons.alpha ${CMAKE_SOURCE_DIR}/cmake/EmbedAsset.cmake
    VERBATIM)
target_sources(nsl_platform PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/connection_icons.c")
target_link_libraries(nsl_platform PUBLIC nsl_ui nsl_artwork nsl_updater ihslib ihslib-hid-sdl PkgConfig::SDL2 PkgConfig::SDL2_TTF
    PkgConfig::FFMPEG PkgConfig::OPUS Threads::Threads nsl_gfx nsl_remote)
target_compile_definitions(nsl_platform PRIVATE NSL_HAVE_SNS=$<BOOL:${NSL_BUILD_SNS}>)
if(NSL_BUILD_SNS)
    target_link_libraries(nsl_platform PUBLIC nsl_sns)
endif()
add_executable(nsteamlink src/main.c)
target_link_libraries(nsteamlink PRIVATE nsl_platform)
if(NSL_DIAGNOSTICS)
    target_sources(nsl_platform PRIVATE platforms/common/packet_diagnostics.c)
    target_sources(nsteamlink PRIVATE platforms/common/packet_diagnostic_wrap.c)
    target_include_directories(nsteamlink PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    foreach(symbol IHS_SessionConnect IHS_UDPSocketReceive IHS_SessionChannelDataReceived IHS_SessionChannelQueuePacket)
        target_link_options(nsteamlink PRIVATE "-Wl,--wrap=${symbol}")
    endforeach()
endif()
if(NSL_PLATFORM STREQUAL "switch")
    target_sources(nsl_platform PRIVATE platforms/switch/rumble.c platforms/switch/preflight.c)
    target_link_options(nsl_platform INTERFACE -Wl,--wrap=SDL_GameControllerRumble)
    target_link_libraries(nsl_platform PUBLIC nx)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(NSL_NACP "${CMAKE_CURRENT_BINARY_DIR}/control.nacp")
    set(NSL_DEFAULT_HACBREWPACK "hacbrewpack")
    if(EXISTS "${CMAKE_SOURCE_DIR}/build/deps/hacBrewPack/hacbrewpack")
        set(NSL_DEFAULT_HACBREWPACK "${CMAKE_SOURCE_DIR}/build/deps/hacBrewPack/hacbrewpack")
    endif()
    set(HACBREWPACK "${NSL_DEFAULT_HACBREWPACK}" CACHE STRING "hacBrewPack executable")
    add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/shortcut_template.c"
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/scripts/build-shortcut.py"
            --root "${CMAKE_SOURCE_DIR}" --output "${CMAKE_CURRENT_BINARY_DIR}/shortcut_template.c"
            --hacbrewpack "${HACBREWPACK}"
        DEPENDS "${CMAKE_SOURCE_DIR}/scripts/build-shortcut.py"
            "${CMAKE_SOURCE_DIR}/third_party/nx-hbloader/source/main.c"
            "${CMAKE_SOURCE_DIR}/third_party/nx-hbloader/source/trampoline.s"
            "${CMAKE_SOURCE_DIR}/third_party/nx-hbloader/Makefile"
            "${CMAKE_SOURCE_DIR}/third_party/nx-hbloader/hbl.json"
            "${CMAKE_SOURCE_DIR}/packaging/switch/application.json"
            "${CMAKE_SOURCE_DIR}/assets/branding/icon.jpg" VERBATIM)
    target_sources(nsl_platform PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/shortcut_template.c")
    add_custom_command(OUTPUT "${NSL_NACP}"
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/scripts/switch-metadata.py"
            --identity "${NSL_IDENTITY_DIR}/build_identity.json" --nacptool "${NX_NACPTOOL_EXE}"
            --output "${NSL_NACP}"
        DEPENDS nsl_identity "${NSL_IDENTITY_DIR}/build_identity.json"
            "${CMAKE_SOURCE_DIR}/scripts/switch-metadata.py" VERBATIM)
    nx_create_nro(nsteamlink OUTPUT nsteamlink.nro NACP "${NSL_NACP}"
        ICON "${CMAKE_SOURCE_DIR}/assets/branding/icon.jpg")
    set(NSL_PRIVATE_SNS_ROMFS "" CACHE PATH "Private SNS fixture RomFS; never a release artifact")
    option(NSL_PRIVATE_SNS_MEDIA "Build the separate private encoded-frame fixture" OFF)
    option(NSL_PRIVATE_SNS_RUNTIME "Build the private full application fixture" OFF)
    if(NSL_PRIVATE_SNS_RUNTIME AND NOT NSL_DIAGNOSTICS)
        message(FATAL_ERROR "Private runtime fixture requires diagnostics in the application objects")
    endif()
    if(NSL_PRIVATE_SNS_ROMFS)
        if(NOT NSL_BUILD_TOOLS OR NOT NSL_BUILD_SNS)
            message(FATAL_ERROR "Private SNS fixture requires SNS and diagnostic tools")
        endif()
        foreach(name profile.bin return.key)
            if(NOT EXISTS "${NSL_PRIVATE_SNS_ROMFS}/${name}")
                message(FATAL_ERROR "Private SNS fixture input is missing")
            endif()
        endforeach()
        foreach(kind network media runtime)
            if(kind STREQUAL "media" AND NOT NSL_PRIVATE_SNS_MEDIA)
                continue()
            endif()
            if(kind STREQUAL "runtime" AND NOT NSL_PRIVATE_SNS_RUNTIME)
                continue()
            endif()
            set(fixture "nsl-sns-${kind}-private")
            add_executable(${fixture} tests/switch_remote_probe.c platforms/switch/system.c)
            if(NOT kind STREQUAL "runtime")
                target_sources(${fixture} PRIVATE tests/remote_live.c)
            endif()
            target_compile_definitions(${fixture} PRIVATE NSL_HAVE_SNS=1
                NSL_LIVE_EXTERNAL_LOG=1 NSL_REMOTE_LIVE_ENTRY=sl_network_probe_run NSL_DIAGNOSTICS=1
                NSL_PRIVATE_MEDIA_FIXTURE=$<STREQUAL:${kind},media>
                NSL_PRIVATE_RUNTIME_FIXTURE=$<STREQUAL:${kind},runtime>)
            target_compile_options(${fixture} PRIVATE -Wall -Wextra -Wno-unknown-pragmas)
            target_include_directories(${fixture} SYSTEM PRIVATE ${MBEDTLS_INCLUDE_DIRS})
            target_link_libraries(${fixture} PRIVATE nsl_sns nsl_ui nx)
            if(kind STREQUAL "runtime")
                target_sources(${fixture} PRIVATE tests/runtime_fixture.c)
                # All fixture policy stays in this separate binary. The real
                # application, media, runtime, decoder and SDK objects are reused.
                target_link_libraries(${fixture} PRIVATE nsl_platform)
                target_include_directories(${fixture} PRIVATE platforms/common
                    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
                foreach(symbol sl_system_init sl_system_shutdown sl_system_data_dir sl_system_running
                        sl_update_config_load sl_ui_tick sl_runtime_create sl_sns_create sl_sns_update IHS_SessionGetReliabilityStats IHS_HIDSDLGetLastSubmittedReport IHS_HIDDeviceStartInputReports IHS_HIDDeviceSDLCreate IHS_HIDManagedDeviceClose
                        IHS_HIDFlushSDLGameControllers IHS_HIDHandleSDLEvent sl_media_gate
                        IHS_SessionConnect IHS_UDPSocketReceive IHS_SessionChannelDataReceived
                        IHS_SessionChannelQueuePacket sl_remote_connection_update
                        curl_easy_recv sendto recvfrom sendmsg recvmsg)
                    target_link_options(${fixture} PRIVATE "-Wl,--wrap=${symbol}")
                endforeach()
            endif()
            nx_generate_nacp("${CMAKE_CURRENT_BINARY_DIR}/sns-${kind}-private.nacp"
                NAME "SNS private ${kind} test" AUTHOR "nsteamlink" VERSION "1")
            nx_create_nro(${fixture} OUTPUT "${fixture}.nro"
                NACP "${CMAKE_CURRENT_BINARY_DIR}/sns-${kind}-private.nacp" ROMFS "${NSL_PRIVATE_SNS_ROMFS}")
            # A raw RomFS directory alone does not track changed file contents.
            add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${fixture}.nro" APPEND
                DEPENDS "${NSL_PRIVATE_SNS_ROMFS}/profile.bin" "${NSL_PRIVATE_SNS_ROMFS}/return.key")
        endforeach()
    endif()
endif()
if(NSL_PLATFORM STREQUAL "desktop")
    add_executable(nsl-diagnostic-log-tests tests/test_diagnostic_log.c platforms/common/diagnostic_log.c)
    add_dependencies(nsl-diagnostic-log-tests nsl_identity)
    target_include_directories(nsl-diagnostic-log-tests PRIVATE src platforms/common ${NSL_IDENTITY_DIR})
    target_compile_definitions(nsl-diagnostic-log-tests PRIVATE NSL_DIAGNOSTICS=1
        NSL_DIAGNOSTIC_PORT=0 NSL_DIAGNOSTIC_SEGMENT_BYTES=4096)
    target_compile_options(nsl-diagnostic-log-tests PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(nsl-diagnostic-log-tests PRIVATE Threads::Threads)
    foreach(symbol accept fdopen fopen stat)
        target_link_options(nsl-diagnostic-log-tests PRIVATE "-Wl,--wrap=${symbol}")
    endforeach()
    add_test(NAME nsl-diagnostic-log COMMAND nsl-diagnostic-log-tests)
    set_tests_properties(nsl-diagnostic-log PROPERTIES TIMEOUT 20)
    add_executable(nsl-lan-transport-tests tests/test_lan_transport.c)
    target_include_directories(nsl-lan-transport-tests PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_compile_options(nsl-lan-transport-tests PRIVATE -Wall -Wextra -Wno-unknown-pragmas -UNDEBUG)
    target_link_libraries(nsl-lan-transport-tests PRIVATE ihslib)
    if(NSL_DIAGNOSTICS)
        target_sources(nsl-lan-transport-tests PRIVATE platforms/common/packet_diagnostics.c
            platforms/common/packet_diagnostic_wrap.c)
        target_include_directories(nsl-lan-transport-tests PRIVATE platforms/common)
        target_compile_definitions(nsl-lan-transport-tests PRIVATE NSL_DIAGNOSTICS=1)
        foreach(symbol IHS_SessionConnect IHS_UDPSocketReceive IHS_SessionChannelDataReceived IHS_SessionChannelQueuePacket)
            target_link_options(nsl-lan-transport-tests PRIVATE "-Wl,--wrap=${symbol}")
        endforeach()
    endif()
    add_test(NAME nsl-lan-transport COMMAND nsl-lan-transport-tests)
    set_tests_properties(nsl-lan-transport PROPERTIES TIMEOUT 20)
    if(NSL_BUILD_TOOLS AND NSL_BUILD_SNS AND NSL_DIAGNOSTICS)
        add_executable(nsl-runtime-probe tests/runtime_probe.c tests/runtime_fixture.c)
        target_link_libraries(nsl-runtime-probe PRIVATE nsl_platform)
        target_include_directories(nsl-runtime-probe PRIVATE platforms/common
            ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
        target_compile_options(nsl-runtime-probe PRIVATE -Wall -Wextra -Wno-unknown-pragmas)
        foreach(symbol sl_system_data_dir sl_system_running sl_update_config_load sl_ui_tick
                sl_runtime_create sl_sns_create sl_sns_update IHS_SessionGetReliabilityStats IHS_HIDSDLGetLastSubmittedReport IHS_HIDDeviceStartInputReports IHS_HIDDeviceSDLCreate IHS_HIDManagedDeviceClose
                        IHS_HIDFlushSDLGameControllers IHS_HIDHandleSDLEvent sl_media_gate
                        IHS_SessionConnect IHS_UDPSocketReceive IHS_SessionChannelDataReceived
                        IHS_SessionChannelQueuePacket sl_remote_connection_update curl_easy_recv
                        curl_multi_add_handle curl_multi_info_read sendto recvfrom sendmsg recvmsg SDL_Init SDL_Quit)
            target_link_options(nsl-runtime-probe PRIVATE "-Wl,--wrap=${symbol}")
        endforeach()
    endif()
    add_executable(nsl-remote-tests tests/test_remote.c platforms/desktop/system.c)
    target_include_directories(nsl-remote-tests PRIVATE ${CMAKE_SOURCE_DIR}/third_party/ihslib/src
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client)
    target_compile_options(nsl-remote-tests PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(nsl-remote-tests PRIVATE nsl_remote nsl_ui)
    add_test(NAME nsl-remote COMMAND nsl-remote-tests)
    if(NSL_DIAGNOSTICS)
        add_executable(nsl-remote-diagnostics-tests tests/test_remote_diagnostics.c)
        target_compile_definitions(nsl-remote-diagnostics-tests PRIVATE NSL_DIAGNOSTICS=1)
        target_compile_options(nsl-remote-diagnostics-tests PRIVATE -Wall -Wextra -UNDEBUG)
        target_link_libraries(nsl-remote-diagnostics-tests PRIVATE nsl_remote)
        foreach(symbol curl_easy_init curl_easy_setopt curl_multi_perform curl_multi_info_read)
            target_link_options(nsl-remote-diagnostics-tests PRIVATE "-Wl,--wrap=${symbol}")
        endforeach()
        add_test(NAME nsl-remote-diagnostics COMMAND nsl-remote-diagnostics-tests)
    endif()
    add_executable(nsl-stream-bridge-tests tests/test_stream_bridge.c)
    target_include_directories(nsl-stream-bridge-tests PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_compile_options(nsl-stream-bridge-tests PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(nsl-stream-bridge-tests PRIVATE nsl_remote)
    add_test(NAME nsl-stream-bridge COMMAND nsl-stream-bridge-tests)
    add_executable(nsl-sdr-wire-tests tests/test_sdr_wire.c)
    target_compile_options(nsl-sdr-wire-tests PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(nsl-sdr-wire-tests PRIVATE nsl_remote)
    add_test(NAME nsl-sdr-wire COMMAND nsl-sdr-wire-tests)
    add_executable(nsl-sdr-policy-tests tests/test_sdr_policy.c)
    target_compile_options(nsl-sdr-policy-tests PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(nsl-sdr-policy-tests PRIVATE nsl_sdr_core)
    add_test(NAME nsl-sdr-policy COMMAND nsl-sdr-policy-tests)
    if(NSL_BUILD_SNS)
        add_executable(nsl-sns-crypto-tests tests/test_sns_crypto.cpp)
        target_compile_features(nsl-sns-crypto-tests PRIVATE cxx_std_17)
        target_compile_options(nsl-sns-crypto-tests PRIVATE -Wall -Wextra -UNDEBUG)
        target_compile_definitions(nsl-sns-crypto-tests PRIVATE VALVE_CRYPTO_ENABLE_25519)
        target_include_directories(nsl-sns-crypto-tests PRIVATE ${NSL_GNS_SOURCE}/src/common
            ${NSL_GNS_SOURCE}/src/public)
        target_link_libraries(nsl-sns-crypto-tests PRIVATE GameNetworkingSockets::GameNetworkingSockets_s)
        add_test(NAME nsl-sns-crypto COMMAND nsl-sns-crypto-tests)
        if(NSL_BUILD_TOOLS)
            add_executable(nsl-sdr-topology-tests tests/test_sdr_topology.cpp)
            target_include_directories(nsl-sdr-topology-tests PRIVATE platforms/common)
            target_link_libraries(nsl-sdr-topology-tests PRIVATE GameNetworkingSockets::GameNetworkingSockets_s)
            add_test(NAME nsl-sdr-topology COMMAND nsl-sdr-topology-tests)
            set_tests_properties(nsl-sdr-topology PROPERTIES TIMEOUT 10)
        endif()
    endif()
    set_tests_properties(nsl-remote PROPERTIES TIMEOUT 20)
    if(NSL_BUILD_TOOLS)
        add_executable(nsl-remote-lifecycle-live tests/remote_lifecycle_live.c platforms/desktop/system.c)
        target_link_libraries(nsl-remote-lifecycle-live PRIVATE nsl_remote nsl_ui)
        target_compile_options(nsl-remote-lifecycle-live PRIVATE -Wall -Wextra)
        target_link_options(nsl-remote-lifecycle-live PRIVATE
            -Wl,--wrap=sl_remote_receive -Wl,--wrap=sl_ws_encode)
        add_executable(nsl-remote-live tests/remote_live.c platforms/desktop/system.c)
        target_link_libraries(nsl-remote-live PRIVATE nsl_remote nsl_ui)
        if(NSL_BUILD_SNS)
            target_compile_definitions(nsl-remote-live PRIVATE NSL_HAVE_SNS=1)
            target_link_libraries(nsl-remote-live PRIVATE nsl_sns)
        endif()
    endif()
    add_executable(nsl-video-contract-tests tests/test_video_contracts.c)
    target_link_libraries(nsl-video-contract-tests PRIVATE nsl_video_contracts Threads::Threads)
    target_compile_options(nsl-video-contract-tests PRIVATE -Wall -Wextra -UNDEBUG)
    add_test(NAME nsl-video-contracts COMMAND nsl-video-contract-tests)
    set_tests_properties(nsl-video-contracts PROPERTIES TIMEOUT 20)
    add_executable(nsl-ui-tests tests/test_ui.c platforms/desktop/system.c)
    target_link_libraries(nsl-ui-tests PRIVATE nsl_ui)
    target_link_options(nsl-ui-tests PRIVATE -Wl,--wrap=rename)
    target_compile_options(nsl-ui-tests PRIVATE -Wall -Wextra -UNDEBUG)
    add_test(NAME nsl-ui COMMAND nsl-ui-tests)
    add_executable(nsl-updater-tests tests/test_updater.c platforms/desktop/system.c)
    target_link_libraries(nsl-updater-tests PRIVATE nsl_updater)
    # Horizon's rename() never replaces; the tests switch between both behaviours.
    target_link_options(nsl-updater-tests PRIVATE -Wl,--wrap=rename)
    target_compile_options(nsl-updater-tests PRIVATE -Wall -Wextra -UNDEBUG)
    add_test(NAME nsl-updater COMMAND nsl-updater-tests)
    set_tests_properties(nsl-updater PROPERTIES TIMEOUT 30)
endif()
if(NSL_PLATFORM STREQUAL "desktop")
    add_executable(nsl-native-tests tests/test_native.c)
    target_include_directories(nsl-native-tests PRIVATE platforms/common)
    target_compile_options(nsl-native-tests PRIVATE -UNDEBUG)
    target_link_libraries(nsl-native-tests PRIVATE nsl_platform)
    add_test(NAME nsl-native COMMAND nsl-native-tests "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/sequential.h264")
    set_tests_properties(nsl-native PROPERTIES ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy;NSL_DATA_DIR=${CMAKE_BINARY_DIR}/native-test-profile" TIMEOUT 20)
endif()
if(NSL_PLATFORM STREQUAL "desktop")
    add_executable(nsl-artwork-tests tests/test_artwork.c platforms/desktop/system.c)
    target_include_directories(nsl-artwork-tests PRIVATE platforms/common)
    target_link_libraries(nsl-artwork-tests PRIVATE nsl_artwork)
    target_compile_options(nsl-artwork-tests PRIVATE -Wall -Wextra -UNDEBUG)
    add_test(NAME nsl-artwork COMMAND nsl-artwork-tests)
    set_tests_properties(nsl-artwork PROPERTIES TIMEOUT 15)
endif()

if(NSL_PLATFORM STREQUAL "desktop")
    add_executable(nsl-launch-tests tests/test_launch_watch.c)
    target_link_libraries(nsl-launch-tests PRIVATE nsl_ui)
    target_compile_options(nsl-launch-tests PRIVATE -UNDEBUG)
    add_test(NAME nsl-launch COMMAND nsl-launch-tests)
endif()

if(NSL_PLATFORM STREQUAL "desktop")
    add_executable(nsl-i18n-tests tests/test_i18n.c platforms/desktop/system.c)
    target_link_libraries(nsl-i18n-tests PRIVATE nsl_ui)
    target_link_options(nsl-i18n-tests PRIVATE -Wl,--wrap=rename)
    target_compile_options(nsl-i18n-tests PRIVATE -UNDEBUG)
    add_test(NAME nsl-i18n COMMAND nsl-i18n-tests)
    add_test(NAME nsl-i18n-catalogs COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/scripts/test-i18n.py")
endif()

if(NSL_PLATFORM STREQUAL "desktop")
    add_executable(nsl-title-tests tests/test_titles.c platforms/desktop/system.c)
    target_include_directories(nsl-title-tests PRIVATE platforms/common)
    target_link_libraries(nsl-title-tests PRIVATE nsl_artwork)
    target_compile_options(nsl-title-tests PRIVATE -UNDEBUG)
    add_test(NAME nsl-titles COMMAND nsl-title-tests)
    set_tests_properties(nsl-titles PROPERTIES TIMEOUT 15)
endif()

if(NSL_PLATFORM STREQUAL "desktop")
    add_executable(nsl-ui-audio-tests tests/test_ui_audio.c)
    target_link_libraries(nsl-ui-audio-tests PRIVATE nsl_ui PkgConfig::SDL2)
    target_compile_options(nsl-ui-audio-tests PRIVATE -UNDEBUG)
    add_test(NAME nsl-ui-audio COMMAND nsl-ui-audio-tests)
    set_tests_properties(nsl-ui-audio PROPERTIES ENVIRONMENT "SDL_AUDIODRIVER=dummy" TIMEOUT 10)
endif()

if(NSL_PLATFORM STREQUAL "desktop")
    add_executable(nsl-rumble-tests tests/test_rumble.c platforms/switch/rumble.c)
    target_include_directories(nsl-rumble-tests PRIVATE tests/fakes)
    target_compile_definitions(nsl-rumble-tests PRIVATE NSL_RUMBLE_TEST=1)
    target_compile_options(nsl-rumble-tests PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(nsl-rumble-tests PRIVATE nsl_ui PkgConfig::SDL2)
    add_test(NAME nsl-rumble COMMAND nsl-rumble-tests)
endif()

if(NSL_PLATFORM STREQUAL "desktop")
    find_package(OpenSSL REQUIRED)
    add_executable(nsl-shortcut-package-tests tests/test_shortcut_package.c platforms/common/shortcut_package.c)
    target_include_directories(nsl-shortcut-package-tests PRIVATE platforms/common)
    target_link_libraries(nsl-shortcut-package-tests PRIVATE OpenSSL::Crypto)
    target_compile_options(nsl-shortcut-package-tests PRIVATE -Wall -Wextra -UNDEBUG)
    add_test(NAME nsl-shortcut-package COMMAND nsl-shortcut-package-tests)
endif()

if(NSL_PLATFORM STREQUAL "desktop")
    add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/shortcut_fixture.c"
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/scripts/test-shortcut-fixture.py"
            "${CMAKE_CURRENT_BINARY_DIR}/shortcut_fixture.c"
        DEPENDS "${CMAKE_SOURCE_DIR}/scripts/test-shortcut-fixture.py" VERBATIM)
    add_executable(nsl-shortcut-install-tests tests/test_shortcut_install.c platforms/switch/shortcut.c
        platforms/common/shortcut_package.c "${CMAKE_CURRENT_BINARY_DIR}/shortcut_fixture.c")
    target_include_directories(nsl-shortcut-install-tests PRIVATE tests/shortcut_fakes platforms/common)
    target_link_libraries(nsl-shortcut-install-tests PRIVATE nsl_ui OpenSSL::Crypto)
    target_compile_options(nsl-shortcut-install-tests PRIVATE -Wall -Wextra -UNDEBUG)
    add_test(NAME nsl-shortcut-install COMMAND nsl-shortcut-install-tests)
    add_library(nsl-preflight-entry OBJECT src/main.c)
    target_link_libraries(nsl-preflight-entry PRIVATE nsl_ui)
    target_compile_definitions(nsl-preflight-entry PRIVATE main=sl_test_entry)
    add_executable(nsl-preflight-tests tests/test_preflight.c platforms/switch/preflight.c
        platforms/desktop/system.c $<TARGET_OBJECTS:nsl-preflight-entry>)
    target_compile_definitions(nsl-preflight-tests PRIVATE NSL_PREFLIGHT_TEST=1)
    target_include_directories(nsl-preflight-tests PRIVATE tests/shortcut_fakes)
    target_link_libraries(nsl-preflight-tests PRIVATE nsl_ui Threads::Threads)
    target_link_options(nsl-preflight-tests PRIVATE -Wl,--wrap=pthread_create -Wl,--wrap=pthread_join -Wl,--wrap=sl_system_now)
    target_compile_options(nsl-preflight-tests PRIVATE -Wall -Wextra -UNDEBUG)
    add_test(NAME nsl-preflight COMMAND nsl-preflight-tests)
    set_tests_properties(nsl-preflight PROPERTIES TIMEOUT 20)
endif()

if(NSL_PLATFORM STREQUAL "desktop")
    add_executable(nsl-video-pipeline-tests tests/test_video_pipeline.c)
    target_link_libraries(nsl-video-pipeline-tests PRIVATE nsl_video_pipeline)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(nsl-video-pipeline-tests PRIVATE -Wl,--wrap=avcodec_open2)
    endif()
    target_include_directories(nsl-video-pipeline-tests PRIVATE ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_compile_options(nsl-video-pipeline-tests PRIVATE -Wall -Wextra -Wno-unknown-pragmas -UNDEBUG)
    add_test(NAME nsl-video-pipeline COMMAND nsl-video-pipeline-tests
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/reordered.h264
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/sequential.h264)
    set_tests_properties(nsl-video-pipeline PROPERTIES TIMEOUT 20)
endif()

if(NSL_PLATFORM STREQUAL "switch" AND NSL_DIAGNOSTICS)
    add_executable(nsl-video-probe tests/switch_video_probe.c)
    target_include_directories(nsl-video-probe PRIVATE platforms/common ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_compile_options(nsl-video-probe PRIVATE -Wall -Wextra -Wno-unknown-pragmas)
    target_link_libraries(nsl-video-probe PRIVATE nsl_gfx nx)
    target_include_directories(nsl-video-probe PRIVATE "${NSL_IDENTITY_DIR}")
    add_dependencies(nsl-video-probe nsl_identity)
    foreach(fixture padding720 padding1080 sequential reordered)
        set(embedded "${CMAKE_CURRENT_BINARY_DIR}/probe_${fixture}.c")
        add_custom_command(OUTPUT "${embedded}"
            COMMAND "${CMAKE_COMMAND}" -DINPUT=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/${fixture}.h264
                -DOUTPUT=${embedded} -DSYMBOL=nsl_probe_${fixture} -P "${CMAKE_SOURCE_DIR}/cmake/EmbedAsset.cmake"
            DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/${fixture}.h264"
                "${CMAKE_SOURCE_DIR}/cmake/EmbedAsset.cmake" VERBATIM)
        target_sources(nsl-video-probe PRIVATE "${embedded}")
    endforeach()
    nx_generate_nacp(OUTPUT video_probe.nacp NAME "NSteamLink Video Probe" AUTHOR "NSteamLink" VERSION "1.0.0")
    nx_create_nro(nsl-video-probe OUTPUT nsl-video-probe.nro NACP "${CMAKE_CURRENT_BINARY_DIR}/video_probe.nacp")
endif()

add_custom_target(nsl_graphics_manifest ALL
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/scripts/graphics-manifest.py"
        --root "${CMAKE_SOURCE_DIR}" --build "${CMAKE_BINARY_DIR}" --backend "${NSL_GFX_BACKEND}"
        --deko-library "${NSL_DEKO3D}"
    DEPENDS nsl_gfx "${CMAKE_SOURCE_DIR}/scripts/graphics-manifest.py" VERBATIM)

if(NSL_PLATFORM STREQUAL "desktop")
    add_executable(nsl-frame-pacer-tests tests/test_frame_pacer.c platforms/common/frame_pacer.c)
    target_include_directories(nsl-frame-pacer-tests PRIVATE platforms/common)
    target_compile_options(nsl-frame-pacer-tests PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(nsl-frame-pacer-tests PRIVATE m)
    target_compile_definitions(nsl-frame-pacer-tests PRIVATE NSL_DIAGNOSTICS=1)
    add_test(NAME nsl-frame-pacer COMMAND nsl-frame-pacer-tests)
    add_executable(nsl-frame-pacer-release-tests tests/test_frame_pacer.c platforms/common/frame_pacer.c)
    target_include_directories(nsl-frame-pacer-release-tests PRIVATE platforms/common)
    target_compile_definitions(nsl-frame-pacer-release-tests PRIVATE NSL_DIAGNOSTICS=0)
    target_compile_options(nsl-frame-pacer-release-tests PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(nsl-frame-pacer-release-tests PRIVATE m)
    add_test(NAME nsl-frame-pacer-release COMMAND nsl-frame-pacer-release-tests)
endif()
