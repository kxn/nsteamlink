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
# Backend is a platform property, not a selectable Switch fallback. Clear old
# caches so an existing SDL Switch build directory also migrates to deko.
unset(NSL_GFX_BACKEND CACHE)
if(NSL_PLATFORM STREQUAL "switch")
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
    platforms/common/ui_renderer.c platforms/common/ui_audio.c platforms/common/player_owner.c platforms/common/runtime.c platforms/${NSL_PLATFORM}/system.c
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
    PkgConfig::FFMPEG Opus::opus Threads::Threads nsl_gfx)
add_executable(nsteamlink src/main.c)
target_link_libraries(nsteamlink PRIVATE nsl_platform)
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
endif()
if(NSL_PLATFORM STREQUAL "desktop")
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
    target_link_libraries(nsl-auth-udp-oracle PRIVATE nsl_stream_settings nsl_video_pipeline)
    target_compile_options(nsl-auth-udp-oracle PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_options(nsl-auth-udp-oracle PRIVATE
        -Wl,--wrap=IHS_SessionChannelControlRequestAuthentication
        -Wl,--wrap=IHS_SessionChannelControlOnAuthentication
        -Wl,--wrap=IHS_SessionChannelControlDrainIncoming
        -Wl,--wrap=IHS_SessionChannelControlOnMessageReceived
        -Wl,--wrap=avcodec_send_packet)
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
    add_test(NAME media_retry_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-retry-process.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle>)
    set_tests_properties(media_retry_udp_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME media_gap_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-gap-process.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle>)
    set_tests_properties(media_gap_udp_official_vectors PROPERTIES TIMEOUT 60)
    add_test(NAME microphone_udp_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-microphone-process.py"
        --receiver $<TARGET_FILE:nsl-auth-udp-oracle>)
    set_tests_properties(microphone_udp_official_vectors PROPERTIES TIMEOUT 60)
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
    target_link_options(nsl-video-timing-oracle PRIVATE -Wl,--wrap=IHS_SessionPacketTimestamp
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
    target_link_options(nsl-video-keyframe-runtime PRIVATE -Wl,--wrap=sl_video_create -Wl,--wrap=avcodec_open2
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
    target_link_options(nsl-video-reset-runtime PRIVATE -Wl,--wrap=sl_video_create -Wl,--wrap=avcodec_open2
        -Wl,--wrap=sl_video_close -Wl,--wrap=sl_video_discard_buffers -Wl,--wrap=sl_video_stop
        -Wl,--wrap=avcodec_flush_buffers -Wl,--wrap=avcodec_free_context
        -Wl,--wrap=sl_media_video_submit_tracked -Wl,--wrap=IHS_SessionPacketsWindowReleaseFrame
        -Wl,--wrap=IHS_SessionPacketTimestamp -Wl,--wrap=IHS_BaseSend
        -Wl,--wrap=IHS_SessionSendControlMessage -Wl,--wrap=IHS_SessionChannelDataLost)
    add_test(NAME video_reset_runtime COMMAND nsl-video-reset-runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/video/sequential.h264)
    set_tests_properties(video_reset_runtime PROPERTIES TIMEOUT 20)
    add_executable(nsl-network-test-runtime tests/network_test_runtime.c)
    target_include_directories(nsl-network-test-runtime PRIVATE platforms/common
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
        ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf ${CMAKE_SOURCE_DIR}/third_party/ihslib/tests/session)
    target_compile_options(nsl-network-test-runtime PRIVATE -UNDEBUG -Wall -Wextra)
    target_link_libraries(nsl-network-test-runtime PRIVATE nsl_platform)
    target_link_options(nsl-network-test-runtime PRIVATE -Wl,--wrap=IHS_ClientStreamingRequest
        -Wl,--wrap=sl_network_stats_save_session)
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
        -Wl,--wrap=sl_audio_recovery_run -Wl,--wrap=sl_audio_recovery_reset)
    add_test(NAME opus_recovery_official_vectors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/scripts/check-steam-opus-recovery.py"
        --receiver $<TARGET_FILE:nsl-opus-recovery-oracle>)
    set_tests_properties(opus_recovery_official_vectors PROPERTIES TIMEOUT 90)
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
        target_link_options(nsl-video-pipeline-tests PRIVATE -Wl,--wrap=avcodec_open2 -Wl,--wrap=avcodec_send_packet -Wl,--wrap=avcodec_receive_frame)
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
