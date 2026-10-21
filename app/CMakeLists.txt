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
include(${CMAKE_SOURCE_DIR}/cmake/Opus.cmake)
pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)
pkg_check_modules(JPEG REQUIRED IMPORTED_TARGET libjpeg)
find_package(Threads REQUIRED)
add_library(nsl_sdr_core STATIC platforms/common/sdr_wire.c platforms/common/sdr_config.c
    platforms/common/sdr_policy.c)
target_include_directories(nsl_sdr_core PUBLIC platforms/common PRIVATE ${CMAKE_SOURCE_DIR}/third_party/jsmn)
target_compile_options(nsl_sdr_core PRIVATE -Wall -Wextra)
add_library(nsl_remote STATIC platforms/common/host_addresses.cpp platforms/common/host_accounts.c platforms/common/host_directory.c platforms/common/remote_wire.c platforms/common/remote_protocol.c
    platforms/common/remote_connection.c platforms/common/stream_bridge.c
    platforms/common/dns_refresh.c platforms/common/dns_config.c platforms/common/dns_policy.c)
target_compile_features(nsl_remote PRIVATE cxx_std_17)
target_include_directories(nsl_remote PUBLIC platforms/common PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/jsmn ${CMAKE_SOURCE_DIR}/third_party/ihslib/src
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client)
target_include_directories(nsl_remote SYSTEM PRIVATE ${MBEDTLS_INCLUDE_DIRS})
target_compile_options(nsl_remote PRIVATE -Wall -Wextra)
target_compile_definitions(nsl_remote PRIVATE NSL_DIAGNOSTICS=$<BOOL:${NSL_DIAGNOSTICS}>)
target_link_libraries(nsl_remote PUBLIC ihslib nsl_sdr_core PkgConfig::CURL ${MBEDCRYPTO_LIBRARY} Threads::Threads)
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
    add_library(nsl_sns STATIC platforms/common/sns_backend.cpp platforms/common/sns_config_cache.c)
    target_compile_features(nsl_sns PRIVATE cxx_std_17)
    target_compile_definitions(nsl_sns PRIVATE NSL_ENABLE_SDR=$<BOOL:${NSL_ENABLE_SDR}>
        NSL_DIAGNOSTICS=$<BOOL:${NSL_DIAGNOSTICS}>)
    target_compile_definitions(nsl_sns PUBLIC NSL_SNS_PROBES=$<BOOL:${NSL_BUILD_TOOLS}>)
    target_compile_options(nsl_sns PRIVATE -Wall -Wextra)
    target_include_directories(nsl_sns PUBLIC platforms/common)
    target_link_libraries(nsl_sns PUBLIC nsl_remote GameNetworkingSockets::GameNetworkingSockets_s
        Threads::Threads)
endif()
add_library(nsl_video_contracts STATIC platforms/common/frame_lifetime.c platforms/common/app_lifecycle.c)
target_include_directories(nsl_video_contracts PUBLIC platforms/common)
target_compile_options(nsl_video_contracts PRIVATE -Wall -Wextra)
set_source_files_properties(platforms/common/video_timing.c PROPERTIES COMPILE_OPTIONS "-ffp-contract=off")
add_library(nsl_video_pipeline STATIC platforms/common/video_pipeline.c platforms/common/video_timing.c)
target_compile_definitions(nsl_video_pipeline PRIVATE NSL_DIAGNOSTICS=$<BOOL:${NSL_DIAGNOSTICS}>)
target_include_directories(nsl_video_pipeline PUBLIC platforms/common
    PRIVATE ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
target_compile_options(nsl_video_pipeline PRIVATE -Wall -Wextra -Wno-unknown-pragmas)
target_link_libraries(nsl_video_pipeline PUBLIC nsl_video_contracts ihslib PkgConfig::FFMPEG Threads::Threads)
if(NSL_PLATFORM STREQUAL "desktop" OR NSL_DIAGNOSTICS)
    set(NSL_VCL_DIR "${CMAKE_CURRENT_BINARY_DIR}/vcl_probe")
    add_custom_command(OUTPUT "${NSL_VCL_DIR}/pcm720.h264" "${NSL_VCL_DIR}/pcm1080.h264"
        "${NSL_VCL_DIR}/vcl_fixture_metadata.h" "${NSL_VCL_DIR}/video_pipeline_capability.c"
        "${NSL_VCL_DIR}/vcl_probe_manifest.json"
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/scripts/prepare-vcl-probe.py"
            --pipeline "${CMAKE_CURRENT_SOURCE_DIR}/platforms/common/video_pipeline.c"
            --fixtures "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/vcl" --output "${NSL_VCL_DIR}"
        DEPENDS "${CMAKE_SOURCE_DIR}/scripts/prepare-vcl-probe.py"
            platforms/common/video_pipeline.c tests/fixtures/video/vcl/manifest.json
            tests/fixtures/video/vcl/pcm720.h264.gz tests/fixtures/video/vcl/pcm1080.h264.gz
        VERBATIM)
    add_custom_target(nsl_vcl_assets DEPENDS "${NSL_VCL_DIR}/pcm720.h264"
        "${NSL_VCL_DIR}/pcm1080.h264" "${NSL_VCL_DIR}/vcl_fixture_metadata.h"
        "${NSL_VCL_DIR}/video_pipeline_capability.c" "${NSL_VCL_DIR}/vcl_probe_manifest.json")
    if(NSL_DIAGNOSTICS)
        add_library(nsl_vcl_capability_pipeline STATIC "${NSL_VCL_DIR}/video_pipeline_capability.c"
            platforms/common/video_timing.c)
        add_dependencies(nsl_vcl_capability_pipeline nsl_vcl_assets)
        target_compile_definitions(nsl_vcl_capability_pipeline PRIVATE NSL_DIAGNOSTICS=1)
        target_include_directories(nsl_vcl_capability_pipeline PUBLIC platforms/common
            PRIVATE ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
        target_compile_options(nsl_vcl_capability_pipeline PRIVATE -Wall -Wextra -Wno-unknown-pragmas)
        target_link_libraries(nsl_vcl_capability_pipeline PUBLIC nsl_video_contracts ihslib
            PkgConfig::FFMPEG Threads::Threads)
    endif()
endif()
# Backend is a platform property, not a selectable Switch fallback. Clear old
# caches so an existing SDL Switch build directory also migrates to deko.
unset(NSL_GFX_BACKEND CACHE)
if(NSL_PLATFORM STREQUAL "switch")
    target_sources(nsl_remote PRIVATE platforms/common/dns_policy_wrap.c)
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
    src/services/host_registry.c src/services/auth_store.c src/services/host_key_store.c src/services/i18n.c
    src/services/update_config.c src/services/video_settings.c)
target_include_directories(nsl_ui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(nsl_ui PRIVATE -Wall -Wextra)
target_link_libraries(nsl_ui PUBLIC m)
add_dependencies(nsl_ui nsl_identity nsl_i18n)
target_include_directories(nsl_ui PUBLIC ${NSL_IDENTITY_DIR} ${NSL_I18N_DIR})
target_compile_definitions(nsl_ui PUBLIC NSL_DIAGNOSTICS=$<BOOL:${NSL_DIAGNOSTICS}> NSL_ADAPTIVE_PACING=$<BOOL:${NSL_ADAPTIVE_PACING}>)
target_compile_definitions(nsl_ui PUBLIC NSL_TEST_FORCE_1080=$<BOOL:${NSL_TEST_FORCE_1080}>)
add_library(nsl_stream_settings STATIC platforms/common/stream_settings.c
    platforms/common/network_stats_file.c)
set_source_files_properties(platforms/common/network_stats_file.c PROPERTIES COMPILE_OPTIONS "-ffp-contract=off")
target_include_directories(nsl_stream_settings PUBLIC src platforms/common
    PRIVATE ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
target_link_libraries(nsl_stream_settings PUBLIC ihslib Threads::Threads PRIVATE ihs-protobuf)
target_compile_options(nsl_stream_settings PRIVATE -Wall -Wextra)
set_source_files_properties(platforms/common/audio_jitter.c PROPERTIES COMPILE_OPTIONS "-ffp-contract=off")
add_library(nsl_platform STATIC platforms/common/application.c platforms/common/sdl_input.c platforms/common/media.c
    platforms/common/audio_recovery.c platforms/common/audio_jitter.c
    platforms/common/shortcut_package.c platforms/${NSL_PLATFORM}/shortcut.c
    platforms/common/ui_renderer.c platforms/common/ui_audio.c platforms/common/player_owner.c platforms/common/diagnostic_log.c platforms/common/runtime.c platforms/${NSL_PLATFORM}/system.c
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
target_link_libraries(nsl_platform PUBLIC nsl_ui nsl_artwork nsl_updater nsl_stream_settings ihslib ihslib-hid-sdl PkgConfig::SDL2 PkgConfig::SDL2_TTF
    PkgConfig::FFMPEG Opus::opus Threads::Threads nsl_gfx nsl_remote)
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
    target_link_options(nsl_platform INTERFACE -Wl,--wrap=getaddrinfo -Wl,--wrap=curl_easy_init)
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
    set(NSL_NACP_NAME "NSteamLink")
    if(NSL_TEST_FORCE_1080)
        set(NSL_NACP_NAME "NSteamLink 1080p Test")
    endif()
    add_custom_command(OUTPUT "${NSL_NACP}"
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/scripts/switch-metadata.py"
            --identity "${NSL_IDENTITY_DIR}/build_identity.json" --nacptool "${NX_NACPTOOL_EXE}"
            --output "${NSL_NACP}" --name "${NSL_NACP_NAME}"
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
                        sl_update_config_load sl_ui_tick sl_runtime_create sl_sns_create sl_sns_create_configured sl_sns_update IHS_SessionGetReliabilityStats IHS_HIDSDLGetLastSubmittedReport IHS_HIDDeviceStartInputReports IHS_HIDDeviceSDLCreate IHS_HIDManagedDeviceClose
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
                sl_runtime_create sl_sns_create sl_sns_create_configured sl_sns_update IHS_SessionGetReliabilityStats IHS_HIDSDLGetLastSubmittedReport IHS_HIDDeviceStartInputReports IHS_HIDDeviceSDLCreate IHS_HIDManagedDeviceClose
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
    add_executable(nsl-dns-refresh-tests tests/test_dns_refresh.c)
    target_compile_options(nsl-dns-refresh-tests PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(nsl-dns-refresh-tests PRIVATE nsl_remote)
    add_test(NAME nsl-dns-refresh COMMAND nsl-dns-refresh-tests)
    add_executable(nsl-dns-policy-tests tests/test_dns_policy.c platforms/common/dns_policy_wrap.c)
    target_compile_options(nsl-dns-policy-tests PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(nsl-dns-policy-tests PRIVATE nsl_remote)
    target_link_options(nsl-dns-policy-tests PRIVATE -Wl,--wrap=sl_dns_current_config
        -Wl,--wrap=curl_easy_setopt)
    add_test(NAME nsl-dns-policy COMMAND nsl-dns-policy-tests)
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
    add_executable(nsl-control-frame-oracle tests/control_frame_oracle.c)
    target_include_directories(nsl-control-frame-oracle PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client)
    target_compile_options(nsl-control-frame-oracle PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(nsl-control-frame-oracle PRIVATE nsl_remote)
    target_link_options(nsl-control-frame-oracle PRIVATE -Wl,--wrap=IHS_CryptoSymmetricEncrypt
        -Wl,--wrap=IHS_BaseSend)
    add_test(NAME control_frame_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-control-frame.py"
        --receiver $<TARGET_FILE:nsl-control-frame-oracle>)
    set_tests_properties(control_frame_official_vectors PROPERTIES TIMEOUT 20)
    add_executable(nsl-sdr-wire-tests tests/test_sdr_wire.c)
    target_compile_options(nsl-sdr-wire-tests PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(nsl-sdr-wire-tests PRIVATE nsl_remote)
    add_test(NAME nsl-sdr-wire COMMAND nsl-sdr-wire-tests)
    add_executable(nsl-sdr-policy-tests tests/test_sdr_policy.c)
    target_compile_options(nsl-sdr-policy-tests PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(nsl-sdr-policy-tests PRIVATE nsl_sdr_core)
    add_test(NAME nsl-sdr-policy COMMAND nsl-sdr-policy-tests)
    if(NSL_BUILD_SNS)
        add_executable(nsl-sns-signal-state-oracle tests/sns_signal_state_oracle.cpp)
        target_compile_features(nsl-sns-signal-state-oracle PRIVATE cxx_std_17)
        target_compile_definitions(nsl-sns-signal-state-oracle PRIVATE NSL_SNS_PROBES=0 NSL_DIAGNOSTICS=0)
        target_include_directories(nsl-sns-signal-state-oracle PRIVATE platforms/common)
        target_compile_options(nsl-sns-signal-state-oracle PRIVATE -Wall -Wextra -UNDEBUG)
        target_link_libraries(nsl-sns-signal-state-oracle PRIVATE nsl_remote
            GameNetworkingSockets::GameNetworkingSockets_s Threads::Threads)
        add_test(NAME sns_signal_state_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-sns-signal-state.py"
            --receiver $<TARGET_FILE:nsl-sns-signal-state-oracle>)
        set_tests_properties(sns_signal_state_official_vectors PROPERTIES TIMEOUT 20)
        add_executable(nsl-sns-receive-oracle tests/sns_receive_oracle.cpp tests/sns_receive_ihs.c)
        target_compile_features(nsl-sns-receive-oracle PRIVATE cxx_std_17)
        target_compile_definitions(nsl-sns-receive-oracle PRIVATE NSL_SNS_PROBES=0 NSL_DIAGNOSTICS=0)
        target_include_directories(nsl-sns-receive-oracle PRIVATE platforms/common
            ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
        target_compile_options(nsl-sns-receive-oracle PRIVATE -Wall -Wextra -UNDEBUG)
        target_link_options(nsl-sns-receive-oracle PRIVATE -Wl,--wrap=IHS_SessionPacketTimestamp
            -Wl,--wrap=IHS_SessionPacketParse -Wl,--wrap=IHS_SessionTransportPrepareUpdate)
        target_link_libraries(nsl-sns-receive-oracle PRIVATE nsl_remote
            GameNetworkingSockets::GameNetworkingSockets_s Threads::Threads)
        add_test(NAME sns_receive_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-sns-receive.py"
            --receiver $<TARGET_FILE:nsl-sns-receive-oracle>)
        set_tests_properties(sns_receive_official_vectors PROPERTIES TIMEOUT 30)
        add_executable(nsl-sns-io-oracle tests/sns_io_oracle.cpp tests/sns_io_ihs.c)
        target_compile_features(nsl-sns-io-oracle PRIVATE cxx_std_17)
        target_include_directories(nsl-sns-io-oracle PRIVATE platforms/common
            ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
        target_compile_options(nsl-sns-io-oracle PRIVATE -Wall -Wextra -UNDEBUG)
        target_link_options(nsl-sns-io-oracle PRIVATE -Wl,--wrap=IHS_SessionPacketTimestamp)
        target_link_libraries(nsl-sns-io-oracle PRIVATE nsl_sns)
        add_test(NAME sns_io_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-sns-io.py"
            --receiver $<TARGET_FILE:nsl-sns-io-oracle>)
        set_tests_properties(sns_io_official_vectors PROPERTIES TIMEOUT 30)
        add_executable(nsl-sns-owner-state-tests tests/test_sns_owner_state.cpp)
        target_compile_features(nsl-sns-owner-state-tests PRIVATE cxx_std_17)
        target_compile_definitions(nsl-sns-owner-state-tests PRIVATE NSL_SNS_PROBES=0 NSL_DIAGNOSTICS=0)
        target_include_directories(nsl-sns-owner-state-tests PRIVATE platforms/common)
        target_compile_options(nsl-sns-owner-state-tests PRIVATE -Wall -Wextra -UNDEBUG)
        target_link_libraries(nsl-sns-owner-state-tests PRIVATE nsl_remote
            GameNetworkingSockets::GameNetworkingSockets_s Threads::Threads)
        add_test(NAME nsl-sns-owner-state COMMAND nsl-sns-owner-state-tests)
        set_tests_properties(nsl-sns-owner-state PROPERTIES TIMEOUT 15)
        add_executable(nsl-sns-initialization-tests tests/test_sns_initialization.cpp)
        target_compile_features(nsl-sns-initialization-tests PRIVATE cxx_std_17)
        target_compile_definitions(nsl-sns-initialization-tests PRIVATE NSL_SNS_PROBES=0 NSL_DIAGNOSTICS=0)
        target_include_directories(nsl-sns-initialization-tests PRIVATE platforms/common)
        target_compile_options(nsl-sns-initialization-tests PRIVATE -Wall -Wextra -UNDEBUG)
        target_link_libraries(nsl-sns-initialization-tests PRIVATE nsl_remote
            GameNetworkingSockets::GameNetworkingSockets_s Threads::Threads)
        foreach(symbol curl_easy_init curl_easy_getinfo curl_multi_perform curl_multi_info_read
            sl_gns_import_trust sl_stream_bridge_create sl_stream_bridge_update sl_stream_bridge_destroy)
            target_link_options(nsl-sns-initialization-tests PRIVATE "-Wl,--wrap=${symbol}")
        endforeach()
        add_test(NAME sns_initialization_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-sns-initialization.py"
            --receiver $<TARGET_FILE:nsl-sns-initialization-tests>)
        set_tests_properties(sns_initialization_official_vectors PROPERTIES TIMEOUT 60)
        add_executable(nsl-sns-state-oracle tests/sns_state_oracle.cpp)
        target_compile_features(nsl-sns-state-oracle PRIVATE cxx_std_17)
        target_include_directories(nsl-sns-state-oracle PRIVATE platforms/common)
        target_compile_options(nsl-sns-state-oracle PRIVATE -Wall -Wextra -UNDEBUG)
        target_link_libraries(nsl-sns-state-oracle PRIVATE nsl_sns)
        add_test(NAME sns_state_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-sns-state.py"
            --receiver $<TARGET_FILE:nsl-sns-state-oracle>)
        set_tests_properties(sns_state_official_vectors PROPERTIES TIMEOUT 25)
        add_test(NAME sns_state_mutation_counterexamples COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/test-steam-sns-state-mutations.py"
            --compiler "${CMAKE_CXX_COMPILER}")
        set_tests_properties(sns_state_mutation_counterexamples PROPERTIES TIMEOUT 90)
        add_executable(nsl-sns-queue-tests tests/test_sns_queue.cpp)
        target_compile_features(nsl-sns-queue-tests PRIVATE cxx_std_17)
        target_include_directories(nsl-sns-queue-tests PRIVATE platforms/common)
        target_compile_options(nsl-sns-queue-tests PRIVATE -Wall -Wextra -UNDEBUG)
        add_test(NAME nsl-sns-queue COMMAND nsl-sns-queue-tests)
        if(NSL_DIAGNOSTICS)
            add_executable(nsl-sns-start-tests tests/test_sns_start.cpp)
            target_compile_features(nsl-sns-start-tests PRIVATE cxx_std_17)
            target_compile_options(nsl-sns-start-tests PRIVATE -Wall -Wextra -UNDEBUG)
            target_compile_definitions(nsl-sns-start-tests PRIVATE NSL_ENABLE_SDR=$<BOOL:${NSL_ENABLE_SDR}>)
            target_include_directories(nsl-sns-start-tests PRIVATE platforms/common)
            target_link_libraries(nsl-sns-start-tests PRIVATE GameNetworkingSockets::GameNetworkingSockets_s)
            target_link_options(nsl-sns-start-tests PRIVATE -Wl,--wrap=setsockopt)
            add_test(NAME nsl-sns-start COMMAND nsl-sns-start-tests)
        endif()
        add_executable(nsl-sns-crypto-tests tests/test_sns_crypto.cpp)
        target_compile_features(nsl-sns-crypto-tests PRIVATE cxx_std_17)
        target_compile_options(nsl-sns-crypto-tests PRIVATE -Wall -Wextra -UNDEBUG)
        target_compile_definitions(nsl-sns-crypto-tests PRIVATE VALVE_CRYPTO_ENABLE_25519)
        target_include_directories(nsl-sns-crypto-tests PRIVATE ${NSL_GNS_SOURCE}/src/common
            ${NSL_GNS_SOURCE}/src/public)
        target_link_libraries(nsl-sns-crypto-tests PRIVATE GameNetworkingSockets::GameNetworkingSockets_s)
        add_test(NAME nsl-sns-crypto COMMAND nsl-sns-crypto-tests)
        add_executable(nsl-local-certificate-oracle tests/local_certificate_oracle.cpp)
        target_compile_features(nsl-local-certificate-oracle PRIVATE cxx_std_17)
        target_compile_options(nsl-local-certificate-oracle PRIVATE -Wall -Wextra -UNDEBUG)
        target_include_directories(nsl-local-certificate-oracle PRIVATE
            ${CMAKE_BINARY_DIR}/third_party/GameNetworkingSockets/src)
        target_link_libraries(nsl-local-certificate-oracle PRIVATE GameNetworkingSockets::GameNetworkingSockets_s)
        add_test(NAME local_certificate_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-local-certificate.py"
            --receiver $<TARGET_FILE:nsl-local-certificate-oracle>)
        set_tests_properties(local_certificate_official_vectors PROPERTIES TIMEOUT 20)
        add_executable(nsl-config-fetch-oracle tests/config_fetch_oracle.cpp)
        target_include_directories(nsl-config-fetch-oracle PRIVATE platforms/common)
        target_compile_options(nsl-config-fetch-oracle PRIVATE -Wall -Wextra -UNDEBUG)
        add_test(NAME config_fetch_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-config-fetch.py"
            --receiver $<TARGET_FILE:nsl-config-fetch-oracle>
            --owner $<TARGET_FILE:nsl-sns-config-refresh-tests>)
        set_tests_properties(config_fetch_official_vectors PROPERTIES TIMEOUT 30)
        add_executable(nsl-sns-config-refresh-tests tests/test_sns_config_refresh.cpp)
        target_compile_features(nsl-sns-config-refresh-tests PRIVATE cxx_std_17)
        target_compile_definitions(nsl-sns-config-refresh-tests PRIVATE NSL_SNS_PROBES=0 NSL_DIAGNOSTICS=0)
        target_include_directories(nsl-sns-config-refresh-tests PRIVATE platforms/common)
        target_compile_options(nsl-sns-config-refresh-tests PRIVATE -Wall -Wextra -UNDEBUG)
        target_link_libraries(nsl-sns-config-refresh-tests PRIVATE nsl_remote
            GameNetworkingSockets::GameNetworkingSockets_s Threads::Threads)
        foreach(symbol curl_easy_init curl_easy_setopt curl_easy_getinfo curl_multi_perform
            curl_multi_info_read sl_gns_import_trust)
            target_link_options(nsl-sns-config-refresh-tests PRIVATE "-Wl,--wrap=${symbol}")
        endforeach()
        add_executable(nsl-config-cache-owner tests/config_cache_owner.c)
        target_compile_definitions(nsl-config-cache-owner PRIVATE NSL_DIAGNOSTICS=0)
        target_compile_options(nsl-config-cache-owner PRIVATE -Wall -Wextra -UNDEBUG)
        target_link_libraries(nsl-config-cache-owner PRIVATE PkgConfig::CURL)
        target_link_options(nsl-config-cache-owner PRIVATE -Wl,--wrap=curl_easy_setopt
            -Wl,--wrap=fwrite -Wl,--wrap=rename)
        add_test(NAME config_cache_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-config-cache.py"
            --receiver $<TARGET_FILE:nsl-config-cache-owner>)
        set_tests_properties(config_cache_official_vectors PROPERTIES TIMEOUT 40)
        add_executable(nsl-sns-cached-initialization-tests tests/test_sns_cached_initialization.cpp)
        target_compile_features(nsl-sns-cached-initialization-tests PRIVATE cxx_std_17)
        target_compile_definitions(nsl-sns-cached-initialization-tests PRIVATE NSL_SNS_PROBES=0 NSL_DIAGNOSTICS=0)
        target_compile_options(nsl-sns-cached-initialization-tests PRIVATE -Wall -Wextra -UNDEBUG)
        target_link_libraries(nsl-sns-cached-initialization-tests PRIVATE nsl_remote
            GameNetworkingSockets::GameNetworkingSockets_s Threads::Threads)
        target_link_options(nsl-sns-cached-initialization-tests PRIVATE -Wl,--wrap=curl_easy_init
            -Wl,--wrap=sl_gns_import_trust)
        add_test(NAME sns_cached_initialization COMMAND nsl-sns-cached-initialization-tests)
        set_tests_properties(sns_cached_initialization PROPERTIES TIMEOUT 15)
        add_executable(nsl-sns-lifetime-owner tests/sns_lifetime_owner.cpp)
        target_compile_features(nsl-sns-lifetime-owner PRIVATE cxx_std_17)
        target_compile_definitions(nsl-sns-lifetime-owner PRIVATE NSL_SNS_PROBES=0 NSL_DIAGNOSTICS=0)
        target_compile_options(nsl-sns-lifetime-owner PRIVATE -Wall -Wextra -UNDEBUG)
        target_include_directories(nsl-sns-lifetime-owner PRIVATE
            ${CMAKE_BINARY_DIR}/third_party/GameNetworkingSockets/src)
        target_link_libraries(nsl-sns-lifetime-owner PRIVATE nsl_remote
            GameNetworkingSockets::GameNetworkingSockets_s Threads::Threads)
        foreach(symbol GameNetworkingSockets_Init GameNetworkingSockets_Kill sl_gns_import_trust
            _ZN25SteamNetworkingSocketsLib19CertStore_CheckCertERK34CMsgSteamDatagramCertificateSignedR28CMsgSteamDatagramCertificatelRA1024_c)
            target_link_options(nsl-sns-lifetime-owner PRIVATE "-Wl,--wrap=${symbol}")
        endforeach()
        add_test(NAME sns_lifetime_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-sns-lifetime.py"
            --receiver $<TARGET_FILE:nsl-sns-lifetime-owner>)
        set_tests_properties(sns_lifetime_official_vectors PROPERTIES TIMEOUT 20)
        add_test(NAME sns_config_refresh_failed COMMAND nsl-sns-config-refresh-tests failure)
        add_test(NAME sns_config_refresh_success_then_failed COMMAND nsl-sns-config-refresh-tests success-then-failure)
        set_tests_properties(sns_config_refresh_failed sns_config_refresh_success_then_failed PROPERTIES TIMEOUT 15)
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
    add_executable(nsl-fec-channel-oracle tests/fec_channels_oracle.c)
    target_include_directories(nsl-fec-channel-oracle PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_link_libraries(nsl-fec-channel-oracle PRIVATE ihs-test-session ihslib)
    target_compile_options(nsl-fec-channel-oracle PRIVATE -Wall -Wextra -Werror
        -Wno-unknown-pragmas -UNDEBUG)
    target_link_options(nsl-fec-channel-oracle PRIVATE -Wl,--wrap=IHS_BaseSend
        -Wl,--wrap=IHS_SessionPacketTimestamp -Wl,--wrap=IHS_SessionPacketParse
        -Wl,--wrap=IHS_FECReceiverAdd -Wl,--wrap=IHS_SessionDeliverReliableFrame)
    add_test(NAME fec_channel_isolation_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-fec-channel-isolation.py"
        --receiver "$<TARGET_FILE:ihs-network-wire-oracle>"
        --channel-receiver "$<TARGET_FILE:nsl-fec-channel-oracle>")
    set_tests_properties(fec_channel_isolation_official_vectors PROPERTIES TIMEOUT 30)
    add_test(NAME live_media_probe_log_contract COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/test-live-media-probe.py")
    add_executable(nsl-video-settings-tests tests/test_video_settings.c)
    target_link_libraries(nsl-video-settings-tests PRIVATE nsl_ui)
    target_compile_options(nsl-video-settings-tests PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_options(nsl-video-settings-tests PRIVATE -Wl,--wrap=rename)
    add_test(NAME nsl-video-settings COMMAND nsl-video-settings-tests)
    add_executable(nsl-resolution-runtime tests/resolution_runtime.c)
    target_include_directories(nsl-resolution-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/common)
    target_compile_options(nsl-resolution-runtime PRIVATE -Wall -Wextra -Wno-unknown-pragmas -UNDEBUG)
    target_link_libraries(nsl-resolution-runtime PRIVATE nsl_platform ihs-test-session)
    target_link_options(nsl-resolution-runtime PRIVATE -Wl,--wrap=sl_system_docked -Wl,--wrap=IHS_ClientStreamingRequest)
    add_test(NAME nsl-resolution-runtime COMMAND nsl-resolution-runtime)
    set_tests_properties(nsl-resolution-runtime PROPERTIES TIMEOUT 30)
    add_executable(nsl-cloud-presence-runtime tests/cloud_presence_runtime.c)
    target_include_directories(nsl-cloud-presence-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf)
    target_compile_options(nsl-cloud-presence-runtime PRIVATE -Wall -Wextra -Wno-unknown-pragmas -UNDEBUG)
    target_link_libraries(nsl-cloud-presence-runtime PRIVATE nsl_platform)
    add_test(NAME cloud_presence_runtime COMMAND nsl-cloud-presence-runtime)
    set_tests_properties(cloud_presence_runtime PROPERTIES TIMEOUT 15)
    add_executable(nsl-account-metadata-oracle tests/account_metadata_oracle.c)
    target_link_libraries(nsl-account-metadata-oracle PRIVATE nsl_remote)
    target_link_options(nsl-account-metadata-oracle PRIVATE -Wl,--wrap=rename)
    target_compile_options(nsl-account-metadata-oracle PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME account_metadata_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-account-metadata.py"
        --receiver $<TARGET_FILE:nsl-account-metadata-oracle>
        --authorization $<TARGET_FILE:ihs-auto-authorization-oracle>)
    set_tests_properties(account_metadata_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME service_pairing_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-service-pairing.py"
        --receiver $<TARGET_FILE:ihs-auto-authorization-oracle>
        --accounts $<TARGET_FILE:nsl-account-metadata-oracle>)
    set_tests_properties(service_pairing_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME account_metadata_storage COMMAND nsl-account-metadata-oracle storage)
    set_tests_properties(account_metadata_storage PROPERTIES TIMEOUT 10)
    add_test(NAME account_metadata_mutation_counterexamples COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/test-steam-account-metadata-mutations.py"
        --compiler "${CMAKE_C_COMPILER}")
    set_tests_properties(account_metadata_mutation_counterexamples PROPERTIES TIMEOUT 30)
    add_executable(nsl-address-cache-oracle tests/address_cache_oracle.c)
    target_link_libraries(nsl-address-cache-oracle PRIVATE nsl_remote)
    target_compile_options(nsl-address-cache-oracle PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME address_cache_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-address-cache.py"
        --receiver $<TARGET_FILE:nsl-address-cache-oracle>)
    set_tests_properties(address_cache_official_vectors PROPERTIES TIMEOUT 30)
    add_test(NAME address_cache_mutation_counterexamples COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/test-steam-address-cache-mutations.py"
        --compiler "${CMAKE_CXX_COMPILER}" --c-compiler "${CMAKE_C_COMPILER}")
    set_tests_properties(address_cache_mutation_counterexamples PROPERTIES TIMEOUT 120)
    add_executable(nsl-host-directory-runtime tests/host_directory_runtime.c)
    target_include_directories(nsl-host-directory-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf)
    target_compile_options(nsl-host-directory-runtime PRIVATE -Wall -Wextra -Wno-unknown-pragmas -UNDEBUG)
    target_link_libraries(nsl-host-directory-runtime PRIVATE nsl_platform)
    target_link_options(nsl-host-directory-runtime PRIVATE -Wl,--wrap=recvfrom -Wl,--wrap=sendto -Wl,--wrap=time)
    add_test(NAME host_directory_runtime COMMAND nsl-host-directory-runtime)
    set_tests_properties(host_directory_runtime PROPERTIES TIMEOUT 15)
    add_executable(nsl-control-route-runtime tests/control_route_runtime.c)
    target_include_directories(nsl-control-route-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf)
    target_compile_definitions(nsl-control-route-runtime PRIVATE NSL_HAVE_SNS=$<BOOL:${NSL_BUILD_SNS}>)
    target_compile_options(nsl-control-route-runtime PRIVATE -Wall -Wextra -Wno-unknown-pragmas -UNDEBUG)
    target_link_libraries(nsl-control-route-runtime PRIVATE nsl_platform)
    target_link_options(nsl-control-route-runtime PRIVATE -Wl,--wrap=recvfrom -Wl,--wrap=sendto
        -Wl,--wrap=time -Wl,--wrap=sl_remote_connection_create
        -Wl,--wrap=sl_remote_connection_protocol -Wl,--wrap=sl_remote_connection_destroy
        -Wl,--wrap=sl_sns_create_configured)
    add_test(NAME control_route_runtime COMMAND nsl-control-route-runtime)
    set_tests_properties(control_route_runtime PROPERTIES TIMEOUT 20)
    add_executable(nsl-service-pairing-runtime tests/service_pairing_runtime.c)
    target_include_directories(nsl-service-pairing-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf)
    target_compile_definitions(nsl-service-pairing-runtime PRIVATE NSL_HAVE_SNS=$<BOOL:${NSL_BUILD_SNS}>)
    target_compile_options(nsl-service-pairing-runtime PRIVATE -UNDEBUG -Wall -Wextra -Werror
        -Wno-unknown-pragmas)
    target_link_libraries(nsl-service-pairing-runtime PRIVATE nsl_platform)
    target_link_options(nsl-service-pairing-runtime PRIVATE
        -Wl,--wrap=sl_remote_connection_create -Wl,--wrap=sl_remote_connection_protocol
        -Wl,--wrap=sl_remote_connection_update -Wl,--wrap=sl_remote_connection_describe
        -Wl,--wrap=sl_remote_connection_destroy -Wl,--wrap=sendto -Wl,--wrap=sl_auth_save
        -Wl,--wrap=IHS_ClientSendControl)
    add_test(NAME service_pairing_runtime COMMAND nsl-service-pairing-runtime)
    set_tests_properties(service_pairing_runtime PROPERTIES TIMEOUT 20)
    add_executable(nsl-pairing-rpc-oracle tests/pairing_rpc_oracle.c)
    target_include_directories(nsl-pairing-rpc-oracle PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf)
    target_compile_definitions(nsl-pairing-rpc-oracle PRIVATE NSL_HAVE_SNS=$<BOOL:${NSL_BUILD_SNS}>)
    target_compile_options(nsl-pairing-rpc-oracle PRIVATE -UNDEBUG -Wall -Wextra -Werror -Wno-unknown-pragmas)
    target_link_libraries(nsl-pairing-rpc-oracle PRIVATE nsl_platform)
    target_link_options(nsl-pairing-rpc-oracle PRIVATE
        -Wl,--wrap=sl_remote_connection_create -Wl,--wrap=sl_remote_connection_protocol
        -Wl,--wrap=sl_remote_connection_update -Wl,--wrap=recvfrom
        -Wl,--wrap=sl_remote_connection_destroy -Wl,--wrap=sendto -Wl,--wrap=time
        -Wl,--wrap=IHS_CryptoRandomUInt32 -Wl,--wrap=IHS_CryptoRandomBytes
        -Wl,--wrap=IHS_CryptoRSAEncrypt -Wl,--wrap=IHS_ClientSendControl
        -Wl,--wrap=IHS_ClientCreateDeviceToken)
    add_test(NAME pairing_rpc_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-pairing-rpc.py"
        --receiver $<TARGET_FILE:nsl-pairing-rpc-oracle>)
    set_tests_properties(pairing_rpc_official_vectors PROPERTIES TIMEOUT 90)
    add_test(NAME request_failure_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-request-failure.py"
        --receiver $<TARGET_FILE:nsl-pairing-rpc-oracle>)
    set_tests_properties(request_failure_official_vectors PROPERTIES TIMEOUT 30)
    add_test(NAME control_update_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-control-update.py"
        --receiver $<TARGET_FILE:nsl-pairing-rpc-oracle>)
    set_tests_properties(control_update_official_vectors PROPERTIES TIMEOUT 45)
    add_executable(nsl-ticket-consumer-runtime tests/ticket_consumer_runtime.c)
    target_include_directories(nsl-ticket-consumer-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf)
    target_compile_definitions(nsl-ticket-consumer-runtime PRIVATE NSL_HAVE_SNS=$<BOOL:${NSL_BUILD_SNS}>)
    target_compile_options(nsl-ticket-consumer-runtime PRIVATE -UNDEBUG -Wall -Wextra -Werror -Wno-unknown-pragmas)
    target_link_libraries(nsl-ticket-consumer-runtime PRIVATE nsl_platform)
    target_link_options(nsl-ticket-consumer-runtime PRIVATE
        -Wl,--wrap=sl_remote_connection_create -Wl,--wrap=sl_remote_connection_protocol
        -Wl,--wrap=sl_remote_connection_update -Wl,--wrap=sl_remote_connection_describe
        -Wl,--wrap=sl_remote_connection_destroy -Wl,--wrap=sendto -Wl,--wrap=recvfrom
        -Wl,--wrap=IHS_ClientSendControl -Wl,--wrap=IHS_SessionCreate
        -Wl,--wrap=IHS_ClientStreamingHandoff
        -Wl,--wrap=IHS_SessionThreadedJoin -Wl,--wrap=sl_system_now
        -Wl,--wrap=IHS_CryptoRandomUInt32 -Wl,--wrap=sl_network_stats_load
        -Wl,--wrap=sl_sns_create_configured -Wl,--wrap=sl_sns_update -Wl,--wrap=sl_sns_get_state
        -Wl,--wrap=sl_sns_session_ready -Wl,--wrap=sl_sns_datagram_transport
        -Wl,--wrap=sl_sns_get_stats -Wl,--wrap=sl_sns_end_reason -Wl,--wrap=sl_sns_destroy
        -Wl,--wrap=sl_sns_config_cache_create -Wl,--wrap=sl_sns_config_cache_update
        -Wl,--wrap=sl_sns_config_cache_destroy)
    set(NSL_TICKET_CONSUMER_ARGS)
    if(NOT NSL_BUILD_SNS)
        list(APPEND NSL_TICKET_CONSUMER_ARGS --without-sns)
    endif()
    add_test(NAME ticket_consumer_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-ticket-consumer.py"
        --receiver $<TARGET_FILE:nsl-ticket-consumer-runtime> ${NSL_TICKET_CONSUMER_ARGS})
    set_tests_properties(ticket_consumer_official_vectors PROPERTIES TIMEOUT 90)
    add_test(NAME shell_handoff_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-shell-handoff.py"
        --receiver $<TARGET_FILE:nsl-ticket-consumer-runtime> ${NSL_TICKET_CONSUMER_ARGS})
    set_tests_properties(shell_handoff_official_vectors PROPERTIES TIMEOUT 90)
    add_executable(nsl-stream-handoff-owner tests/stream_handoff_owner.c)
    target_include_directories(nsl-stream-handoff-owner PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client)
    target_compile_options(nsl-stream-handoff-owner PRIVATE -UNDEBUG -Wall -Wextra -Werror)
    target_link_libraries(nsl-stream-handoff-owner PRIVATE nsl_remote)
    target_link_options(nsl-stream-handoff-owner PRIVATE -Wl,--wrap=IHS_CryptoRandomUInt32
        -Wl,--wrap=IHS_ClientSendControl)
    add_test(NAME stream_handoff_owner COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-shell-handoff.py"
        --receiver $<TARGET_FILE:nsl-ticket-consumer-runtime>
        --owner $<TARGET_FILE:nsl-stream-handoff-owner> --owner-only)
    set_tests_properties(stream_handoff_owner PROPERTIES TIMEOUT 15)
    if(NSL_BUILD_SNS)
        add_test(NAME sns_client_call_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-sns-client-call.py"
            --receiver $<TARGET_FILE:nsl-ticket-consumer-runtime>)
        set_tests_properties(sns_client_call_official_vectors PROPERTIES TIMEOUT 45)
    endif()
    add_executable(nsl-resolution-render tests/test_resolution_render.c)
    target_include_directories(nsl-resolution-render PRIVATE platforms/common ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_link_libraries(nsl-resolution-render PRIVATE nsl_gfx)
    target_compile_options(nsl-resolution-render PRIVATE -Wall -Wextra -Wno-unknown-pragmas -UNDEBUG)
    add_test(NAME nsl-resolution-render COMMAND nsl-resolution-render
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/padding1080.h264)
    set_tests_properties(nsl-resolution-render PROPERTIES ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_RENDER_DRIVER=software" TIMEOUT 30)
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
    add_executable(nsl-network-stats-file-oracle tests/network_stats_file_oracle.c)
    target_include_directories(nsl-network-stats-file-oracle PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_link_libraries(nsl-network-stats-file-oracle PRIVATE nsl_stream_settings ihs-test-session)
    target_compile_options(nsl-network-stats-file-oracle PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_options(nsl-network-stats-file-oracle PRIVATE
        -Wl,--wrap=malloc -Wl,--wrap=fclose -Wl,--wrap=rename)
    add_test(NAME network_stats_file_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-stats-file.py"
        --receiver $<TARGET_FILE:nsl-network-stats-file-oracle>)
    set_tests_properties(network_stats_file_official_vectors PROPERTIES TIMEOUT 90)
    add_executable(nsl-stream-settings-tests tests/test_stream_settings.c platforms/desktop/system.c)
    target_include_directories(nsl-stream-settings-tests PRIVATE ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_link_libraries(nsl-stream-settings-tests PRIVATE nsl_stream_settings nsl_ui ihs-protobuf)
    target_link_options(nsl-stream-settings-tests PRIVATE -Wl,--wrap=rename -Wl,--wrap=fclose)
    target_compile_options(nsl-stream-settings-tests PRIVATE -Wall -Wextra -UNDEBUG)
    add_test(NAME nsl-stream-settings COMMAND nsl-stream-settings-tests)
    set_tests_properties(nsl-stream-settings PROPERTIES TIMEOUT 20)
    add_executable(nsl-auth-udp-oracle tests/auth_udp_oracle.c)
    target_include_directories(nsl-auth-udp-oracle PRIVATE ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_link_libraries(nsl-auth-udp-oracle PRIVATE nsl_platform)
    target_compile_options(nsl-auth-udp-oracle PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_options(nsl-auth-udp-oracle PRIVATE
        -Wl,--wrap=IHS_SessionChannelControlRequestAuthentication
        -Wl,--wrap=IHS_SessionChannelControlOnAuthentication
        -Wl,--wrap=IHS_SessionChannelControlDrainIncoming
        -Wl,--wrap=IHS_SessionChannelControlOnMessageReceived
        -Wl,--wrap=IHS_FrameTrackerBeginInput
        -Wl,--wrap=IHS_BufferClear
        -Wl,--wrap=IHS_SessionChannelAdd
        -Wl,--wrap=IHS_SessionChannelDataLost
        -Wl,--wrap=IHS_UDPSocketSend
        -Wl,--wrap=IHS_SessionChannelDataReceiveReliableFrame
        -Wl,--wrap=avcodec_send_packet -Wl,--wrap=sl_audio_recovery_run
        -Wl,--wrap=opus_multistream_decoder_create -Wl,--wrap=opus_multistream_decode_float
        -Wl,--wrap=sl_audio_jitter_pop -Wl,--wrap=sl_audio_jitter_push -Wl,--wrap=SDL_OpenAudioDevice
        -Wl,--wrap=IHS_UDPSocketReceive -Wl,--wrap=IHS_StreamClockFeedback
        -Wl,--wrap=IHS_SessionUnreliableUpdateAt -Wl,--wrap=IHS_SessionUnreliableReceived)
    add_test(NAME auth_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-auth-process.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle>)
    set_tests_properties(auth_udp_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME negotiation_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-negotiation-process.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle>)
    set_tests_properties(negotiation_udp_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME network_test_fec_flow_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-test-fec-flow.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle>)
    set_tests_properties(network_test_fec_flow_vectors PROPERTIES TIMEOUT 90)
    add_test(NAME media_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-media-process.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle>)
    set_tests_properties(media_udp_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME media_load_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-load-process.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle>)
    set_tests_properties(media_load_udp_official_vectors PROPERTIES TIMEOUT 90)
    add_test(NAME media_pressure_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-pressure-process.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle>
        --output "${CMAKE_BINARY_DIR}/steam-pressure-native.json")
    set_tests_properties(media_pressure_udp_official_vectors PROPERTIES TIMEOUT 120)
    add_test(NAME media_fec_reorder_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/test-steam-fec-reorder-contract.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle>)
    set_tests_properties(media_fec_reorder_udp_official_vectors PROPERTIES TIMEOUT 120)
    add_test(NAME media_large_fec_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-large-process.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle>
        --output "${CMAKE_BINARY_DIR}/steam-large-native.json")
    set_tests_properties(media_large_fec_udp_official_vectors PROPERTIES TIMEOUT 90)
    add_test(NAME media_large_fec_burst_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-large-process.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle> --burst
        --output "${CMAKE_BINARY_DIR}/steam-large-burst-native.json")
    set_tests_properties(media_large_fec_burst_udp_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME media_retry_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-retry-process.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle>)
    set_tests_properties(media_retry_udp_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME media_gap_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-gap-process.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle>)
    set_tests_properties(media_gap_udp_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME media_burst_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-gap-process.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle> --burst)
    set_tests_properties(media_burst_udp_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME microphone_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-microphone-process.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle>)
    set_tests_properties(microphone_udp_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME audio_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-audio-process.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle>)
    set_tests_properties(audio_udp_official_vectors PROPERTIES TIMEOUT 90)
    add_test(NAME rx_capture_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-rx-capture.py"
        --receiver $<TARGET_FILE:ihs-network-wire-oracle>)
    set_tests_properties(rx_capture_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME microphone_schedule_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-microphone-schedule.py"
        --receiver $<TARGET_FILE:ihs-microphone-schedule-oracle>)
    set_tests_properties(microphone_schedule_official_vectors PROPERTIES TIMEOUT 30)
    add_executable(nsl-stream-settings-oracle tests/stream_settings_oracle.c)
    target_link_libraries(nsl-stream-settings-oracle PRIVATE nsl_stream_settings)
    target_compile_options(nsl-stream-settings-oracle PRIVATE -UNDEBUG)
    add_test(NAME stream_settings_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-client-settings-io.py"
        --receiver $<TARGET_FILE:nsl-stream-settings-oracle>)
    set_tests_properties(stream_settings_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME stream_presets_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-client-presets.py"
        --receiver $<TARGET_FILE:nsl-stream-settings-oracle>)
    set_tests_properties(stream_presets_official_vectors PROPERTIES TIMEOUT 90)
    add_executable(nsl-video-timing-oracle tests/video_timing_oracle.c)
    target_include_directories(nsl-video-timing-oracle PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/common)
    target_compile_definitions(nsl-video-timing-oracle PRIVATE NSL_DIAGNOSTICS=$<BOOL:${NSL_DIAGNOSTICS}>)
    target_compile_options(nsl-video-timing-oracle PRIVATE -UNDEBUG -Wall -Wextra -Wno-unknown-pragmas)
    target_link_libraries(nsl-video-timing-oracle PRIVATE nsl_platform ihs-test-session)
    target_link_options(nsl-video-timing-oracle PRIVATE -Wl,--wrap=IHS_SessionChannelDataThink -Wl,--wrap=IHS_SessionPacketTimestamp
        -Wl,--wrap=pthread_join
        -Wl,--wrap=sl_system_video_cpu_count -Wl,--wrap=fopen
        -Wl,--wrap=avcodec_open2 -Wl,--wrap=avcodec_send_packet -Wl,--wrap=avcodec_receive_frame -Wl,--wrap=avcodec_flush_buffers
        -Wl,--wrap=av_parser_parse2 -Wl,--wrap=sl_video_timing_update
        -Wl,--wrap=IHS_SessionVideoDecodeFeedback -Wl,--wrap=IHS_SessionVideoRequestReset -Wl,--wrap=IHS_SessionChannelQueuePacket
        -Wl,--wrap=sl_gfx_present -Wl,--wrap=sl_video_open_ex
        -Wl,--wrap=sl_media_video_start_tracked
        -Wl,--wrap=IHS_SessionVideoDecoderInfo
        -Wl,--wrap=IHS_FrameTicketVideoDecodeStage
        -Wl,--wrap=sl_video_select -Wl,--wrap=IHS_FrameTicketUploadStage
        -Wl,--wrap=IHS_SessionPacketsWindowReleaseFrame -Wl,--wrap=IHS_BaseSend
        -Wl,--wrap=IHS_SessionSendControlMessage -Wl,--wrap=IHS_FrameTicketComplete)
    add_test(NAME video_timing_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-video-timing.py"
        --receiver $<TARGET_FILE:nsl-video-timing-oracle>)
    set_tests_properties(video_timing_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME video_present_avcodec_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-video-avcodec.py"
        --receiver $<TARGET_FILE:nsl-video-timing-oracle>)
    set_tests_properties(video_present_avcodec_vectors PROPERTIES TIMEOUT 90)
    add_test(NAME video_avcodec_recovery_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-video-recovery.py"
        --receiver $<TARGET_FILE:nsl-video-timing-oracle>)
    set_tests_properties(video_avcodec_recovery_vectors PROPERTIES TIMEOUT 90)
    add_test(NAME video_format_handoff COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-format-handoff.py"
        --receiver $<TARGET_FILE:nsl-video-timing-oracle>)
    set_tests_properties(video_format_handoff PROPERTIES TIMEOUT 120)
    add_test(NAME player_hardware_config_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-player-config.py"
        --receiver $<TARGET_FILE:nsl-video-timing-oracle>)
    set_tests_properties(player_hardware_config_vectors PROPERTIES TIMEOUT 90)
    add_test(NAME decoder_info_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-decoder-info.py"
        --receiver $<TARGET_FILE:nsl-video-timing-oracle>)
    set_tests_properties(decoder_info_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME decoder_threads_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-decode-threads.py"
        --receiver $<TARGET_FILE:nsl-video-timing-oracle>)
    set_tests_properties(decoder_threads_official_vectors PROPERTIES TIMEOUT 120)
    add_executable(nsl-video-keyframe-runtime tests/video_keyframe_runtime.c)
    target_include_directories(nsl-video-keyframe-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/common)
    target_compile_definitions(nsl-video-keyframe-runtime PRIVATE NSL_DIAGNOSTICS=$<BOOL:${NSL_DIAGNOSTICS}>)
    target_compile_options(nsl-video-keyframe-runtime PRIVATE -UNDEBUG -Wall -Wextra -Wno-unknown-pragmas)
    target_link_libraries(nsl-video-keyframe-runtime PRIVATE nsl_platform ihs-test-session)
    target_link_options(nsl-video-keyframe-runtime PRIVATE -Wl,--wrap=IHS_SessionChannelDataThink -Wl,--wrap=sl_video_create -Wl,--wrap=avcodec_open2
        -Wl,--wrap=avcodec_flush_buffers -Wl,--wrap=sl_video_discard_buffers -Wl,--wrap=avcodec_send_packet
        -Wl,--wrap=IHS_SessionPacketsWindowReleaseFrame -Wl,--wrap=IHS_SessionPacketTimestamp
        -Wl,--wrap=IHS_BaseSend -Wl,--wrap=IHS_SessionSendControlMessage
        -Wl,--wrap=IHS_SessionChannelDataLost -Wl,--wrap=IHS_FrameTicketComplete)
    add_test(NAME video_keyframe_runtime COMMAND nsl-video-keyframe-runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/sequential.h264)
    set_tests_properties(video_keyframe_runtime PROPERTIES TIMEOUT 20)
    add_executable(nsl-video-reset-runtime tests/video_reset_runtime.c)
    target_include_directories(nsl-video-reset-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/common)
    target_compile_definitions(nsl-video-reset-runtime PRIVATE NSL_DIAGNOSTICS=$<BOOL:${NSL_DIAGNOSTICS}>)
    target_compile_options(nsl-video-reset-runtime PRIVATE -UNDEBUG -Wall -Wextra -Wno-unknown-pragmas)
    target_link_libraries(nsl-video-reset-runtime PRIVATE nsl_platform ihs-test-session)
    target_link_options(nsl-video-reset-runtime PRIVATE -Wl,--wrap=IHS_SessionChannelDataThink -Wl,--wrap=sl_video_create -Wl,--wrap=avcodec_open2
        -Wl,--wrap=sl_video_close -Wl,--wrap=sl_video_discard_buffers -Wl,--wrap=sl_video_stop
        -Wl,--wrap=avcodec_flush_buffers -Wl,--wrap=avcodec_free_context
        -Wl,--wrap=avcodec_receive_frame -Wl,--wrap=av_packet_alloc
        -Wl,--wrap=sl_media_video_submit_tracked -Wl,--wrap=IHS_SessionPacketsWindowReleaseFrame
        -Wl,--wrap=IHS_SessionPacketTimestamp -Wl,--wrap=IHS_BaseSend
        -Wl,--wrap=IHS_SessionSendControlMessage -Wl,--wrap=IHS_SessionChannelDataLost)
    add_test(NAME video_reset_runtime COMMAND nsl-video-reset-runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/sequential.h264)
    set_tests_properties(video_reset_runtime PROPERTIES TIMEOUT 20)
    foreach(mode freeze-before freeze-during packet-oom)
        add_test(NAME video_stop_${mode} COMMAND nsl-video-reset-runtime
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/sequential.h264 --${mode})
        set_tests_properties(video_stop_${mode} PROPERTIES TIMEOUT 20)
    endforeach()
    # Actual client worker, real condition waits and stop/join/destroy.
    add_executable(nsl-discovery-error-runtime tests/discovery_error_runtime.c)
    # Differential oracle; no probe code is linked into products.
    add_executable(nsl-discovery-send-runtime tests/discovery_send_runtime.c)
    target_include_directories(nsl-discovery-send-runtime PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_compile_options(nsl-discovery-send-runtime PRIVATE -Wall -Wextra -Werror -Wno-unknown-pragmas)
    target_link_libraries(nsl-discovery-send-runtime PRIVATE ihslib ihs-platforms ihslib)
    target_link_options(nsl-discovery-send-runtime PRIVATE -Wl,--wrap=socket -Wl,--wrap=close
        -Wl,--wrap=sendto -Wl,--wrap=IHS_UDPBroadcastAddresses -Wl,--wrap=recvfrom -Wl,--wrap=fcntl
        -Wl,--wrap=IHS_ClientBroadcast)
    add_test(NAME discovery_send_official_vectors COMMAND "${Python3_EXECUTABLE}" -O
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-discovery-send.py"
        --receiver $<TARGET_FILE:nsl-discovery-send-runtime>)
    set_tests_properties(discovery_send_official_vectors PROPERTIES TIMEOUT 45)
    add_executable(nsl-discovery-rounds-runtime tests/discovery_rounds_runtime.c)
    target_include_directories(nsl-discovery-rounds-runtime PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_compile_options(nsl-discovery-rounds-runtime PRIVATE -Wall -Wextra -Werror -Wno-unknown-pragmas)
    target_link_libraries(nsl-discovery-rounds-runtime PRIVATE ihslib ihs-platforms ihslib)
    target_link_options(nsl-discovery-rounds-runtime PRIVATE -Wl,--wrap=malloc -Wl,--wrap=time -Wl,--wrap=getpid
        -Wl,--wrap=IHS_DiscoveryRandomInt -Wl,--wrap=IHS_UDPBroadcastAddresses -Wl,--wrap=sendto
        -Wl,--wrap=IHS_ClientStreamingCallback -Wl,--wrap=IHS_ThreadCreate -Wl,--wrap=socket
        -Wl,--wrap=IHS_ClientDiscoveryEndCycle)
    add_test(NAME discovery_rounds_official_vectors COMMAND "${Python3_EXECUTABLE}" -O
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-discovery-rounds.py"
        --receiver $<TARGET_FILE:nsl-discovery-rounds-runtime>)
    set_tests_properties(discovery_rounds_official_vectors PROPERTIES TIMEOUT 45)
    add_test(NAME discovery_joint_official_vectors COMMAND "${Python3_EXECUTABLE}" -O
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-discovery-joint.py"
        --receiver $<TARGET_FILE:nsl-discovery-rounds-runtime>)
    set_tests_properties(discovery_joint_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME discovery_backlog_cancel COMMAND nsl-discovery-rounds-runtime backlog_cancel)
    add_test(NAME discovery_backlog_wrap COMMAND nsl-discovery-rounds-runtime backlog_wrap)
    set_tests_properties(discovery_backlog_cancel discovery_backlog_wrap PROPERTIES TIMEOUT 25)
    add_executable(nsl-client-startup-runtime tests/client_startup_runtime.c)
    target_include_directories(nsl-client-startup-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf)
    target_compile_options(nsl-client-startup-runtime PRIVATE -Wall -Wextra -Werror -Wno-unknown-pragmas)
    target_link_libraries(nsl-client-startup-runtime PRIVATE nsl_platform)
    target_link_options(nsl-client-startup-runtime PRIVATE -Wl,--wrap=malloc -Wl,--wrap=calloc
        -Wl,--wrap=IHS_MutexCreate -Wl,--wrap=IHS_MutexDestroy
        -Wl,--wrap=IHS_CondCreate -Wl,--wrap=IHS_CondDestroy
        -Wl,--wrap=IHS_QueueCreate -Wl,--wrap=IHS_QueueDestroy -Wl,--wrap=IHS_QueueItemObtain
        -Wl,--wrap=IHS_TimerCreate -Wl,--wrap=IHS_UDPSocketOpen
        -Wl,--wrap=IHS_UDPSocketSetBlocking
        -Wl,--wrap=socket -Wl,--wrap=close -Wl,--wrap=sendto
        -Wl,--wrap=IHS_ThreadCreate -Wl,--wrap=IHS_ThreadJoin
        -Wl,--wrap=IHS_ClientCreate -Wl,--wrap=IHS_ClientCreatePolled
        -Wl,--wrap=IHS_ClientEnableDiscovery -Wl,--wrap=IHS_ClientDisableDiscovery -Wl,--wrap=IHS_UDPSocketReceive)
    add_test(NAME discovery_startup_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-discovery-startup.py"
        --receiver $<TARGET_FILE:nsl-client-startup-runtime>)
    set_tests_properties(discovery_startup_official_vectors PROPERTIES TIMEOUT 45)
    add_test(NAME discovery_pause_rejection COMMAND nsl-client-startup-runtime pause_rejection)
    set_tests_properties(discovery_pause_rejection PROPERTIES TIMEOUT 10)
    foreach(fault client_alloc base_mutex receive_cond timer_node timer_queue timer_mutex timer_thread
                  socket_alloc socket_fd socket_mutex discovery_context discovery_task poll_buffer poll_nonblock)
        add_test(NAME polled_startup_${fault} COMMAND nsl-client-startup-runtime polled_${fault})
        set_tests_properties(polled_startup_${fault} PROPERTIES TIMEOUT 10)
    endforeach()
    target_include_directories(nsl-discovery-error-runtime PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_compile_options(nsl-discovery-error-runtime PRIVATE -Wall -Wextra -Werror -Wno-unknown-pragmas)
    target_link_libraries(nsl-discovery-error-runtime PRIVATE ihslib ihs-platforms ihslib)
    target_link_options(nsl-discovery-error-runtime PRIVATE -Wl,--wrap=recvfrom
        -Wl,--wrap=IHS_CondWaitTimeout -Wl,--wrap=IHS_CondSignal
        -Wl,--wrap=IHS_ThreadJoin -Wl,--wrap=IHS_CondDestroy -Wl,--wrap=IHS_CondCreate
        -Wl,--wrap=IHS_UDPSocketSetBlocking)
    add_test(NAME discovery_receive_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-discovery.py"
        --receiver $<TARGET_FILE:nsl-discovery-error-runtime>)
    add_test(NAME discovery_cycles_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-discovery-cycles.py"
        --receiver $<TARGET_FILE:nsl-discovery-error-runtime>)
    set_tests_properties(discovery_receive_official_vectors discovery_cycles_official_vectors PROPERTIES TIMEOUT 30)
    add_executable(nsl-video-stop-queue-runtime tests/video_stop_queue_runtime.c)
    target_include_directories(nsl-video-stop-queue-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/common)
    target_compile_options(nsl-video-stop-queue-runtime PRIVATE -UNDEBUG -Wall -Wextra -Wno-unknown-pragmas)
    target_link_libraries(nsl-video-stop-queue-runtime PRIVATE nsl_platform ihs-test-session)
    target_link_options(nsl-video-stop-queue-runtime PRIVATE
        -Wl,--wrap=IHS_SessionChannelDataReceiveFrame -Wl,--wrap=IHS_SessionChannelDataThink
        -Wl,--wrap=IHS_ThreadJoin -Wl,--wrap=sl_media_video_submit_tracked
        -Wl,--wrap=IHS_SessionChannelDataLost -Wl,--wrap=IHS_SessionPacketTimestamp
        -Wl,--wrap=IHS_BaseSend -Wl,--wrap=avcodec_open2
        -Wl,--wrap=avcodec_send_packet -Wl,--wrap=avcodec_receive_frame)
    foreach(warm 0 1)
        foreach(freeze 0 1)
            add_test(NAME video_stop_queue_${warm}_${freeze} COMMAND nsl-video-stop-queue-runtime
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/sequential.h264 ${warm} ${freeze})
            set_tests_properties(video_stop_queue_${warm}_${freeze} PROPERTIES TIMEOUT 25)
        endforeach()
    endforeach()
    add_executable(nsl-network-test-pin-retry-runtime tests/network_test_pin_retry_runtime.c)
    target_include_directories(nsl-network-test-pin-retry-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/session)
    target_compile_options(nsl-network-test-pin-retry-runtime PRIVATE -UNDEBUG -Wall -Wextra)
    target_compile_definitions(nsl-network-test-pin-retry-runtime PRIVATE NSL_HAVE_SNS=$<BOOL:${NSL_BUILD_SNS}>)
    target_link_libraries(nsl-network-test-pin-retry-runtime PRIVATE nsl_platform)
    target_link_options(nsl-network-test-pin-retry-runtime PRIVATE -Wl,--wrap=IHS_ClientStreamingRequest
        -Wl,--wrap=IHS_ClientSetDiscoveryCallbacks -Wl,--wrap=IHS_SessionCreate
        -Wl,--wrap=IHS_SessionThreadedJoin -Wl,--wrap=IHS_SessionDestroy
        -Wl,--wrap=IHS_SessionGetNetworkTestResult -Wl,--wrap=IHS_SessionDisconnect
        -Wl,--wrap=IHS_ClientStreamingEstablished -Wl,--wrap=IHS_SessionSetDatagramTransport
        -Wl,--wrap=IHS_ClientUpdate
        -Wl,--wrap=sl_sns_create_configured -Wl,--wrap=sl_sns_update -Wl,--wrap=sl_sns_get_state
        -Wl,--wrap=sl_sns_session_ready -Wl,--wrap=sl_sns_datagram_transport
        -Wl,--wrap=sl_sns_get_stats -Wl,--wrap=sl_sns_end_reason -Wl,--wrap=sl_sns_destroy
        -Wl,--wrap=sl_sns_config_cache_update)
    add_test(NAME network_test_pin_retry COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-test-pin-retry.py"
        --receiver $<TARGET_FILE:nsl-network-test-pin-retry-runtime>)
    set_tests_properties(network_test_pin_retry PROPERTIES TIMEOUT 80)
    add_test(NAME network_test_pin_retry_cancel_join COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-test-pin-retry.py"
        --receiver $<TARGET_FILE:nsl-network-test-pin-retry-runtime> --cancel-join)
    set_tests_properties(network_test_pin_retry_cancel_join PROPERTIES TIMEOUT 20)
    add_test(NAME network_test_pin_retry_completed COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-test-pin-retry.py"
        --receiver $<TARGET_FILE:nsl-network-test-pin-retry-runtime> --completed)
    set_tests_properties(network_test_pin_retry_completed PROPERTIES TIMEOUT 130)
    if(NSL_BUILD_SNS)
        add_test(NAME network_test_pin_retry_sdk COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-test-pin-retry.py"
            --receiver $<TARGET_FILE:nsl-network-test-pin-retry-runtime> --sdk)
        set_tests_properties(network_test_pin_retry_sdk PROPERTIES TIMEOUT 80)
        foreach(variant sdk-fail sdk-session-fail)
            add_test(NAME network_test_pin_retry_${variant} COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-test-pin-retry.py"
                --receiver $<TARGET_FILE:nsl-network-test-pin-retry-runtime> --${variant})
            set_tests_properties(network_test_pin_retry_${variant} PROPERTIES TIMEOUT 20)
        endforeach()
    endif()
    add_executable(nsl-network-test-failure-runtime tests/network_test_failure_runtime.c)
    target_include_directories(nsl-network-test-failure-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/session)
    target_compile_options(nsl-network-test-failure-runtime PRIVATE -UNDEBUG -Wall -Wextra)
    target_link_libraries(nsl-network-test-failure-runtime PRIVATE nsl_platform)
    target_link_options(nsl-network-test-failure-runtime PRIVATE -Wl,--wrap=IHS_ClientStreamingRequest
        -Wl,--wrap=sl_runtime_read_facts -Wl,--wrap=IHS_ClientSetDiscoveryCallbacks
        -Wl,--wrap=IHS_SessionThreadedJoin -Wl,--wrap=IHS_SessionDestroy
        -Wl,--wrap=IHS_SessionGetNetworkTestResult -Wl,--wrap=IHS_ClientUpdate)
    add_test(NAME network_test_failure_runtime COMMAND nsl-network-test-failure-runtime)
    set_tests_properties(network_test_failure_runtime PROPERTIES TIMEOUT 40)
    add_test(NAME network_test_late_control COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-test-late-control.py"
        --receiver $<TARGET_FILE:nsl-network-test-failure-runtime>)
    set_tests_properties(network_test_late_control PROPERTIES TIMEOUT 90)
    add_test(NAME network_test_error_overlap COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-test-error-overlap.py"
        --receiver $<TARGET_FILE:nsl-network-test-failure-runtime>)
    set_tests_properties(network_test_error_overlap PROPERTIES TIMEOUT 45)
    if(NSL_BUILD_SNS)
        add_test(NAME network_test_sdk_failure COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-test-sdk-failure.py"
            --receiver $<TARGET_FILE:nsl-ticket-consumer-runtime>)
        set_tests_properties(network_test_sdk_failure PROPERTIES TIMEOUT 90)
    endif()
    add_executable(nsl-host-key-store tests/host_key_store.c src/services/host_key_store.c)
    target_include_directories(nsl-host-key-store PRIVATE src)
    target_compile_options(nsl-host-key-store PRIVATE -UNDEBUG -Wall -Wextra)
    target_link_options(nsl-host-key-store PRIVATE -Wl,--wrap=rename)
    add_test(NAME host_key_store COMMAND nsl-host-key-store)
    add_executable(nsl-pairing-runtime tests/pairing_runtime.c)
    target_include_directories(nsl-pairing-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/session)
    target_compile_options(nsl-pairing-runtime PRIVATE -UNDEBUG -Wall -Wextra)
    target_link_libraries(nsl-pairing-runtime PRIVATE nsl_platform)
    target_link_options(nsl-pairing-runtime PRIVATE -Wl,--wrap=IHS_ClientAuthorizationRequest
        -Wl,--wrap=IHS_ClientSend -Wl,--wrap=IHS_ClientSendControl -Wl,--wrap=IHS_ClientBroadcast
        -Wl,--wrap=sl_auth_save -Wl,--wrap=sl_system_random
        -Wl,--wrap=IHS_ClientStreamingRequest -Wl,--wrap=IHS_CryptoRandomBytes
        -Wl,--wrap=sl_network_stats_load -Wl,--wrap=sl_host_key_save
        -Wl,--wrap=IHS_ClientSetDiscoveryCallbacks
        -Wl,--wrap=sl_remote_connection_update)
    add_test(NAME pairing_runtime COMMAND nsl-pairing-runtime)
    set_tests_properties(pairing_runtime PROPERTIES TIMEOUT 60)
    add_executable(nsl-network-test-runtime tests/network_test_runtime.c)
    add_executable(nsl-connection-wait-oracle tests/connection_wait_oracle.c)
    target_include_directories(nsl-connection-wait-oracle PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/common)
    target_compile_options(nsl-connection-wait-oracle PRIVATE -UNDEBUG -Wall -Wextra)
    target_link_libraries(nsl-connection-wait-oracle PRIVATE nsl_platform ihs-test-session)
    target_include_directories(nsl-network-test-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/session)
    target_compile_options(nsl-network-test-runtime PRIVATE -UNDEBUG -Wall -Wextra)
    target_link_libraries(nsl-network-test-runtime PRIVATE nsl_platform)
    target_link_options(nsl-network-test-runtime PRIVATE -Wl,--wrap=IHS_ClientStreamingRequest
        -Wl,--wrap=IHS_ClientSetDiscoveryCallbacks
        -Wl,--wrap=sl_network_stats_save_session -Wl,--wrap=sl_system_now
        -Wl,--wrap=stream_media_get_snapshot)
    add_test(NAME network_test_runtime COMMAND nsl-network-test-runtime)
    set_tests_properties(network_test_runtime PROPERTIES TIMEOUT 120)
    add_executable(nsl-player-owner-runtime tests/player_owner_runtime.c)
    target_include_directories(nsl-player-owner-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/common)
    target_compile_definitions(nsl-player-owner-runtime PRIVATE NSL_DIAGNOSTICS=$<BOOL:${NSL_DIAGNOSTICS}>)
    target_compile_options(nsl-player-owner-runtime PRIVATE -UNDEBUG -Wall -Wextra -Wno-unknown-pragmas)
    target_link_libraries(nsl-player-owner-runtime PRIVATE nsl_platform ihs-test-session)
    target_link_options(nsl-player-owner-runtime PRIVATE -Wl,--wrap=IHS_SessionThreadedJoin
        -Wl,--wrap=IHS_SessionDestroy -Wl,--wrap=sl_media_end_stream_player
        -Wl,--wrap=SDL_OpenAudioDevice -Wl,--wrap=SDL_CloseAudioDevice -Wl,--wrap=SDL_PauseAudioDevice
        -Wl,--wrap=sl_audio_jitter_init -Wl,--wrap=IHS_BaseSend -Wl,--wrap=IHS_SessionPacketTimestamp)
    add_test(NAME player_owner_runtime COMMAND nsl-player-owner-runtime 1)
    add_test(NAME player_owner_runtime_unfocused COMMAND nsl-player-owner-runtime 0)
    set_tests_properties(player_owner_runtime player_owner_runtime_unfocused PROPERTIES TIMEOUT 15)
    add_executable(nsl-player-owner-oracle tests/player_owner_oracle.c platforms/common/player_owner.c)
    target_include_directories(nsl-player-owner-oracle PRIVATE platforms/common)
    target_compile_options(nsl-player-owner-oracle PRIVATE -UNDEBUG -Wall -Wextra)
    add_test(NAME player_owner_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-player-owner.py"
        --policy $<TARGET_FILE:nsl-player-owner-oracle> --player $<TARGET_FILE:nsl-audio-player-oracle>)
    set_tests_properties(player_owner_official_vectors PROPERTIES TIMEOUT 90)
    add_executable(nsl-audio-player-oracle tests/audio_player_oracle.c)
    target_include_directories(nsl-audio-player-oracle PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/common)
    target_compile_options(nsl-audio-player-oracle PRIVATE -UNDEBUG -Wall -Wextra -Werror=format)
    target_link_libraries(nsl-audio-player-oracle PRIVATE nsl_platform ihs-test-session)
    target_link_options(nsl-audio-player-oracle PRIVATE -Wl,--wrap=SDL_OpenAudioDevice
        -Wl,--wrap=SDL_PauseAudioDevice -Wl,--wrap=SDL_CloseAudioDevice
        -Wl,--wrap=sl_audio_jitter_init -Wl,--wrap=sl_audio_jitter_push -Wl,--wrap=sl_audio_suspend
        -Wl,--wrap=sl_audio_recovery_run -Wl,--wrap=IHS_SessionPacketTimestamp
        -Wl,--wrap=IHS_SessionChannelDataReceiveReliableFrame)
    add_test(NAME audio_player_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-audio-player.py"
        --receiver $<TARGET_FILE:nsl-audio-player-oracle>)
    set_tests_properties(audio_player_official_vectors PROPERTIES TIMEOUT 90)
    add_executable(nsl-audio-playback-oracle tests/audio_playback_oracle.c)
    target_include_directories(nsl-audio-playback-oracle PRIVATE platforms/common ${MBEDTLS_INCLUDE_DIRS})
    target_compile_options(nsl-audio-playback-oracle PRIVATE -UNDEBUG -Wall -Wextra)
    target_link_libraries(nsl-audio-playback-oracle PRIVATE nsl_platform ${MBEDCRYPTO_LIBRARY})
    target_link_options(nsl-audio-playback-oracle PRIVATE -Wl,--wrap=SDL_OpenAudioDevice
        -Wl,--wrap=SDL_PauseAudioDevice)
    add_test(NAME audio_playback_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-audio-jitter.py"
        --receiver $<TARGET_FILE:nsl-audio-playback-oracle> --playback)
    set_tests_properties(audio_playback_official_vectors PROPERTIES TIMEOUT 120)
    add_executable(nsl-audio-jitter-oracle tests/audio_jitter_oracle.c platforms/common/audio_jitter.c)
    target_include_directories(nsl-audio-jitter-oracle PRIVATE platforms/common ${MBEDTLS_INCLUDE_DIRS})
    target_compile_options(nsl-audio-jitter-oracle PRIVATE -UNDEBUG -Wall -Wextra)
    target_link_libraries(nsl-audio-jitter-oracle PRIVATE ${MBEDCRYPTO_LIBRARY} m)
    add_test(NAME audio_jitter_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-audio-jitter.py"
        --receiver $<TARGET_FILE:nsl-audio-jitter-oracle>)
    set_tests_properties(audio_jitter_official_vectors PROPERTIES TIMEOUT 60)
    add_executable(nsl-raw-audio-oracle tests/raw_audio_oracle.c)
    target_include_directories(nsl-raw-audio-oracle PRIVATE platforms/common ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_compile_options(nsl-raw-audio-oracle PRIVATE -UNDEBUG -Wall -Wextra)
    target_link_libraries(nsl-raw-audio-oracle PRIVATE nsl_platform)
    target_link_options(nsl-raw-audio-oracle PRIVATE -Wl,--wrap=sl_audio_jitter_push)
    add_test(NAME raw_audio_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-raw-audio.py"
        --receiver $<TARGET_FILE:nsl-raw-audio-oracle>)
    set_tests_properties(raw_audio_official_vectors PROPERTIES TIMEOUT 60)
    add_executable(nsl-opus-recovery-oracle tests/opus_recovery_oracle.c)
    target_include_directories(nsl-opus-recovery-oracle PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/common)
    target_compile_options(nsl-opus-recovery-oracle PRIVATE -UNDEBUG -Wall -Wextra)
    target_link_libraries(nsl-opus-recovery-oracle PRIVATE nsl_platform ihs-test-session)
    target_link_options(nsl-opus-recovery-oracle PRIVATE -Wl,--wrap=sl_audio_jitter_push
        -Wl,--wrap=SDL_OpenAudioDevice -Wl,--wrap=SDL_PauseAudioDevice
        -Wl,--wrap=opus_multistream_decode_float -Wl,--wrap=opus_multistream_decoder_create
        -Wl,--wrap=sl_audio_recovery_run -Wl,--wrap=sl_audio_recovery_reset
        -Wl,--wrap=IHS_ThreadJoin -Wl,--wrap=opus_multistream_decoder_destroy)
    add_test(NAME opus_recovery_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-opus-recovery.py"
        --receiver $<TARGET_FILE:nsl-opus-recovery-oracle>)
    set_tests_properties(opus_recovery_official_vectors PROPERTIES TIMEOUT 90)
    add_executable(nsl-decoder-stop-queue-oracle tests/decoder_stop_queue_oracle.c)
    target_include_directories(nsl-decoder-stop-queue-oracle PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/common)
    target_compile_options(nsl-decoder-stop-queue-oracle PRIVATE -UNDEBUG -Wall -Wextra -Werror
        -Wno-unknown-pragmas)
    target_link_libraries(nsl-decoder-stop-queue-oracle PRIVATE nsl_platform ihs-test-session)
    target_link_options(nsl-decoder-stop-queue-oracle PRIVATE
        -Wl,--wrap=IHS_ThreadCreate -Wl,--wrap=IHS_ThreadJoin
        -Wl,--wrap=IHS_SessionChannelDataThink -Wl,--wrap=IHS_SessionChannelDataReceiveFrame
        -Wl,--wrap=IHS_SessionPacketsWindowReleaseFrame -Wl,--wrap=sl_audio_recovery_run
        -Wl,--wrap=opus_multistream_decode_float -Wl,--wrap=opus_multistream_decoder_destroy
        -Wl,--wrap=sl_audio_jitter_push -Wl,--wrap=SDL_OpenAudioDevice
        -Wl,--wrap=SDL_PauseAudioDevice -Wl,--wrap=SDL_CloseAudioDevice)
    add_executable(nsl-audio-gap-policy-oracle tests/audio_gap_policy_oracle.c)
    target_include_directories(nsl-audio-gap-policy-oracle PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_link_libraries(nsl-audio-gap-policy-oracle PRIVATE nsl_platform)
    target_compile_options(nsl-audio-gap-policy-oracle PRIVATE -UNDEBUG -Wall -Wextra -Werror)
    add_test(NAME audio_gap_policy_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-audio-gap-policy.py"
        --receiver $<TARGET_FILE:nsl-audio-gap-policy-oracle>
        --media-receiver $<TARGET_FILE:nsl-opus-recovery-oracle>)
    set_tests_properties(audio_gap_policy_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME audio_stop_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-audio-stop.py"
        --receiver $<TARGET_FILE:nsl-opus-recovery-oracle>)
    set_tests_properties(audio_stop_official_vectors PROPERTIES TIMEOUT 90)
    add_test(NAME decoder_stop_queue_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-decoder-stop-queue.py"
        --receiver $<TARGET_FILE:nsl-decoder-stop-queue-oracle>)
    set_tests_properties(decoder_stop_queue_official_vectors PROPERTIES TIMEOUT 90)
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
    add_executable(nsl-vcl-product-tests tests/test_vcl_fixture.c)
    add_dependencies(nsl-vcl-product-tests nsl_vcl_assets)
    target_include_directories(nsl-vcl-product-tests PRIVATE "${NSL_VCL_DIR}"
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_link_libraries(nsl-vcl-product-tests PRIVATE nsl_video_pipeline)
    target_compile_options(nsl-vcl-product-tests PRIVATE -Wall -Wextra -Wno-unknown-pragmas -UNDEBUG)
    add_test(NAME vcl_fixture_production_guard COMMAND nsl-vcl-product-tests "${NSL_VCL_DIR}")
    set_tests_properties(vcl_fixture_production_guard PROPERTIES TIMEOUT 20)
    add_test(NAME vcl_fixture_reproducibility COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/generate-vcl-fixtures.py" --check)
    add_test(NAME switch_vcl_probe_log_contract COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/test-switch-vcl-probe.py")
    set_tests_properties(vcl_fixture_reproducibility switch_vcl_probe_log_contract PROPERTIES TIMEOUT 20)
    if(NSL_DIAGNOSTICS)
        add_executable(nsl-vcl-capability-tests tests/test_vcl_fixture.c)
        add_dependencies(nsl-vcl-capability-tests nsl_vcl_assets)
        target_include_directories(nsl-vcl-capability-tests PRIVATE "${NSL_VCL_DIR}"
            ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
        target_compile_definitions(nsl-vcl-capability-tests PRIVATE NSL_VCL_CAPABILITY_TEST=1)
        target_compile_options(nsl-vcl-capability-tests PRIVATE -Wall -Wextra -Wno-unknown-pragmas -UNDEBUG)
        target_link_libraries(nsl-vcl-capability-tests PRIVATE nsl_vcl_capability_pipeline)
        add_test(NAME vcl_fixture_capability COMMAND nsl-vcl-capability-tests "${NSL_VCL_DIR}")
        set_tests_properties(vcl_fixture_capability PROPERTIES TIMEOUT 20)
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_executable(nsl-media-decode-boundary-tests tests/test_media_decode_boundary.c)
        target_include_directories(nsl-media-decode-boundary-tests PRIVATE
            ${CMAKE_SOURCE_DIR}/third_party/ihslib/src
            ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/common)
        target_link_libraries(nsl-media-decode-boundary-tests PRIVATE nsl_video_pipeline ihs-test-session)
        target_compile_options(nsl-media-decode-boundary-tests PRIVATE
            -Wall -Wextra -Wno-unknown-pragmas -UNDEBUG)
        target_link_options(nsl-media-decode-boundary-tests PRIVATE -Wl,--wrap=IHS_BaseSend
            -Wl,--wrap=IHS_SessionPacketTimestamp -Wl,--wrap=IHS_SessionChannelDataReceiveFrame
            -Wl,--wrap=IHS_SessionChannelDataLost)
        add_test(NAME media_decode_boundary COMMAND nsl-media-decode-boundary-tests
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/recovery720.h264)
        set_tests_properties(media_decode_boundary PROPERTIES TIMEOUT 30)
    endif()
    add_executable(nsl-video-recovery-probe-tests tests/test_video_recovery_probe.c)
    target_include_directories(nsl-video-recovery-probe-tests PRIVATE platforms/common ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_link_libraries(nsl-video-recovery-probe-tests PRIVATE nsl_video_pipeline)
    target_compile_options(nsl-video-recovery-probe-tests PRIVATE -Wall -Wextra -Wno-unknown-pragmas -UNDEBUG)
    add_test(NAME video_recovery_probe_fixture COMMAND nsl-video-recovery-probe-tests
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/recovery720.h264)
    set_tests_properties(video_recovery_probe_fixture PROPERTIES TIMEOUT 30)
    add_test(NAME switch_recovery_probe_log_contract COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/test-switch-recovery-probe.py")
    set_tests_properties(switch_recovery_probe_log_contract PROPERTIES TIMEOUT 15)
    add_executable(nsl-video-pipeline-tests tests/test_video_pipeline.c)
    target_link_libraries(nsl-video-pipeline-tests PRIVATE nsl_video_pipeline)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(nsl-video-pipeline-tests PRIVATE -Wl,--wrap=avcodec_open2 -Wl,--wrap=avcodec_send_packet -Wl,--wrap=avcodec_receive_frame)
    endif()
    target_include_directories(nsl-video-pipeline-tests PRIVATE ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_compile_options(nsl-video-pipeline-tests PRIVATE -Wall -Wextra -Wno-unknown-pragmas -UNDEBUG)
    add_test(NAME nsl-video-pipeline COMMAND nsl-video-pipeline-tests
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/reordered.h264
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/sequential.h264)
    set_tests_properties(nsl-video-pipeline PROPERTIES TIMEOUT 20)
endif()

if(NSL_DIAGNOSTICS)
    add_executable(nsl-live-media-probe tests/live_media_probe.c)
    target_include_directories(nsl-live-media-probe PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_compile_options(nsl-live-media-probe PRIVATE -Wall -Wextra -Werror -Wno-unknown-pragmas)
    target_link_libraries(nsl-live-media-probe PRIVATE nsl_platform)
    target_link_options(nsl-live-media-probe PRIVATE
        "-Wl,-Map=${CMAKE_CURRENT_BINARY_DIR}/nsl-live-media-probe.map"
        -Wl,--wrap=IHS_SessionUnreliableReceived -Wl,--wrap=IHS_FECReceiverAdd
        -Wl,--wrap=IHS_SessionChannelDataReceiveReliableFrame
        -Wl,--wrap=IHS_SessionChannelDataLost -Wl,--wrap=IHS_UDPSocketSend
        -Wl,--wrap=IHS_SessionChannelDataReceiveFrame -Wl,--wrap=sl_media_video_submit_tracked
        -Wl,--wrap=IHS_SessionVideoDecodeFeedback
        -Wl,--wrap=IHS_SessionChannelControlSend -Wl,--wrap=IHS_SessionQueuePacketResult
        -Wl,--wrap=IHS_SessionChannelControlOnNegotiation
        -Wl,--wrap=sl_stream_settings_load -Wl,--wrap=sl_stream_settings_save -Wl,--wrap=sl_auth_save)
    if(NSL_PLATFORM STREQUAL "switch")
        nx_create_nro(nsl-live-media-probe OUTPUT nsl-live-media-probe.nro)
    else()
        add_executable(nsl-live-media-observer-tests tests/test_live_media_observers.c)
        target_include_directories(nsl-live-media-observer-tests PRIVATE platforms/common
            ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
        target_compile_options(nsl-live-media-observer-tests PRIVATE -Wall -Wextra -Werror
            -Wno-unknown-pragmas -UNDEBUG)
        target_link_libraries(nsl-live-media-observer-tests PRIVATE nsl_platform)
        target_link_options(nsl-live-media-observer-tests PRIVATE -Wl,--wrap=IHS_BufferPointer
            -Wl,--wrap=sl_stream_settings_load -Wl,--wrap=sl_stream_settings_save -Wl,--wrap=sl_auth_save)
        add_test(NAME live_media_probe_observers COMMAND nsl-live-media-observer-tests)
        add_executable(nsl-live-media-fec-settings-tests tests/test_live_media_fec_settings.c
            platforms/desktop/system.c)
        target_include_directories(nsl-live-media-fec-settings-tests PRIVATE platforms/common
            ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
        target_compile_options(nsl-live-media-fec-settings-tests PRIVATE -Wall -Wextra -Werror
            -Wno-unknown-pragmas -UNDEBUG)
        target_link_libraries(nsl-live-media-fec-settings-tests PRIVATE nsl_stream_settings
            nsl_ui ihs-protobuf)
        target_link_options(nsl-live-media-fec-settings-tests PRIVATE
            -Wl,--wrap=sl_stream_settings_load -Wl,--wrap=sl_stream_settings_save -Wl,--wrap=sl_auth_save)
        add_test(NAME live_media_probe_fec_settings COMMAND nsl-live-media-fec-settings-tests)
        add_executable(nsl-live-media-config-wire-tests tests/test_live_media_config_wire.c)
        target_include_directories(nsl-live-media-config-wire-tests PRIVATE platforms/common
            ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
        target_compile_options(nsl-live-media-config-wire-tests PRIVATE -Wall -Wextra -Werror
            -Wno-unknown-pragmas -UNDEBUG)
        target_link_libraries(nsl-live-media-config-wire-tests PRIVATE ihs-test-session
            ihslib ihs-platforms ihslib)
        target_link_options(nsl-live-media-config-wire-tests PRIVATE
            -Wl,--wrap=IHS_SessionChannelControlSend -Wl,--wrap=IHS_SessionQueuePacketResult
            -Wl,--wrap=IHS_SessionChannelControlOnNegotiation -Wl,--wrap=IHS_BaseSend)
        add_test(NAME live_media_probe_config_wire COMMAND nsl-live-media-config-wire-tests)
        set_tests_properties(live_media_probe_config_wire PROPERTIES TIMEOUT 15)
        add_executable(nsl-live-media-fec-loss-tests tests/test_live_media_fec_loss.c)
        target_include_directories(nsl-live-media-fec-loss-tests PRIVATE platforms/common
            ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
        target_compile_options(nsl-live-media-fec-loss-tests PRIVATE -Wall -Wextra -Werror
            -Wno-unknown-pragmas -UNDEBUG)
        target_link_libraries(nsl-live-media-fec-loss-tests PRIVATE nsl_platform)
        get_target_property(NSL_LIVE_PROBE_TEST_LINK_OPTIONS nsl-live-media-probe LINK_OPTIONS)
        list(FILTER NSL_LIVE_PROBE_TEST_LINK_OPTIONS EXCLUDE REGEX "^-Wl,-Map=")
        target_link_options(nsl-live-media-fec-loss-tests PRIVATE ${NSL_LIVE_PROBE_TEST_LINK_OPTIONS})
        add_test(NAME live_media_probe_fec_loss COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/test-live-media-fec-loss.py"
            --receiver "$<TARGET_FILE:nsl-live-media-fec-loss-tests>")
        add_executable(nsl-live-media-gap-observer-tests tests/test_live_media_gap_observer.c)
        target_include_directories(nsl-live-media-gap-observer-tests PRIVATE
            ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
        target_compile_options(nsl-live-media-gap-observer-tests PRIVATE -Wall -Wextra -Werror
            -Wno-unknown-pragmas -UNDEBUG)
        target_link_libraries(nsl-live-media-gap-observer-tests PRIVATE ihslib)
        add_test(NAME live_media_probe_gap_observer COMMAND nsl-live-media-gap-observer-tests)
    endif()
endif()
if(NSL_PLATFORM STREQUAL "switch" AND NSL_DIAGNOSTICS)
    add_executable(nsl-vcl-probe tests/switch_vcl_probe.c)
    target_include_directories(nsl-vcl-probe PRIVATE platforms/common "${NSL_VCL_DIR}"
        "${NSL_IDENTITY_DIR}" ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_compile_options(nsl-vcl-probe PRIVATE -Wall -Wextra -Wno-unknown-pragmas)
    # Resolve every pipeline function from the generated capability copy before
    # nsl_gfx's normal dependency. Verify the actual archive provider/link map.
    target_link_libraries(nsl-vcl-probe PRIVATE nsl_vcl_capability_pipeline nsl_gfx nx)
    target_link_options(nsl-vcl-probe PRIVATE -Wl,--wrap=av_nvtegra_map_realloc
        "-Wl,-Map=${CMAKE_CURRENT_BINARY_DIR}/nsl-vcl-probe.map")
    add_dependencies(nsl-vcl-probe nsl_identity nsl_vcl_assets)
    foreach(fixture pcm720 pcm1080)
        set(embedded "${NSL_VCL_DIR}/embed_${fixture}.c")
        add_custom_command(OUTPUT "${embedded}"
            COMMAND "${CMAKE_COMMAND}" -DINPUT=${NSL_VCL_DIR}/${fixture}.h264
                -DOUTPUT=${embedded} -DSYMBOL=nsl_vcl_${fixture}
                -P "${CMAKE_SOURCE_DIR}/cmake/EmbedAsset.cmake"
            DEPENDS "${NSL_VCL_DIR}/${fixture}.h264" "${CMAKE_SOURCE_DIR}/cmake/EmbedAsset.cmake"
            VERBATIM)
        target_sources(nsl-vcl-probe PRIVATE "${embedded}")
    endforeach()
    nx_generate_nacp(OUTPUT vcl_probe.nacp NAME "NSteamLink VCL Probe" AUTHOR "NSteamLink" VERSION "1.0.0")
    nx_create_nro(nsl-vcl-probe OUTPUT nsl-vcl-probe.nro NACP "${CMAKE_CURRENT_BINARY_DIR}/vcl_probe.nacp")
    add_executable(nsl-video-probe tests/switch_video_probe.c)
    target_include_directories(nsl-video-probe PRIVATE platforms/common ${CMAKE_SOURCE_DIR}/third_party/ihslib/src)
    target_compile_options(nsl-video-probe PRIVATE -Wall -Wextra -Wno-unknown-pragmas)
    target_link_libraries(nsl-video-probe PRIVATE nsl_gfx nx)
    target_include_directories(nsl-video-probe PRIVATE "${NSL_IDENTITY_DIR}")
    add_dependencies(nsl-video-probe nsl_identity)
    foreach(fixture padding720 padding1080 sequential reordered recovery720)
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
