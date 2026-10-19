cmake_minimum_required(VERSION 3.22)

project(nsteamlink
    VERSION 0.4.0
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

option(NSL_ADAPTIVE_PACING "Enable legacy publication estimator metrics on deko (official timestamp gate is unconditional)" ON)
option(NSL_DIAGNOSTICS "Compile advanced diagnostics, UDP console and log collection" OFF)
option(NSL_BUILD_TOOLS "Build standalone Switch diagnostic tools" ${NSL_DIAGNOSTICS})
option(NSL_TEST_FORCE_1080 "Build a clearly labelled manual-test app that always requests/renders 1080p" OFF)
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
    if(TARGET ihs-fec-oracle)
        find_package(Python3 COMPONENTS Interpreter REQUIRED)
        add_test(NAME media_input_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-media-input.py"
            --receiver $<TARGET_FILE:ihs-media-input-oracle>)
        set_tests_properties(media_input_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME frame_stats_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-frame-stats.py"
            --receiver $<TARGET_FILE:ihs-frame-stats-oracle>)
        set_tests_properties(frame_stats_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME frame_stats_tracked_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-frame-stats.py"
            --receiver $<TARGET_FILE:ihs-frame-stats-oracle> --tracked)
        add_test(NAME frame_stats_batched_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-frame-stats.py"
            --receiver $<TARGET_FILE:ihs-frame-stats-oracle> --batched)
        set_tests_properties(frame_stats_tracked_official_vectors frame_stats_batched_official_vectors
            PROPERTIES TIMEOUT 60)
        add_test(NAME fec_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-fec-receiver.py"
            --receiver $<TARGET_FILE:ihs-fec-oracle>)
        set_tests_properties(fec_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME transport_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-transport.py"
            --receiver $<TARGET_FILE:ihs-transport-oracle>)
        set_tests_properties(transport_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME client_config_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-client-config.py"
            --receiver $<TARGET_FILE:ihs-client-config-oracle>)
        set_tests_properties(client_config_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME reliable_sender_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-outgoing.py"
            --receiver $<TARGET_FILE:ihs-retry-sender-oracle>)
        set_tests_properties(reliable_sender_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME outgoing_engine_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-outgoing-engine.py"
            --receiver $<TARGET_FILE:ihs-outgoing-oracle>)
        set_tests_properties(outgoing_engine_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME connect_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-connect.py"
            --receiver $<TARGET_FILE:ihs-connect-oracle>)
        set_tests_properties(connect_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME disconnect_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-disconnect.py"
            --receiver $<TARGET_FILE:ihs-disconnect-oracle>)
        set_tests_properties(disconnect_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME send_admission_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-send-admission.py"
            --receiver $<TARGET_FILE:ihs-send-admission-oracle>)
        set_tests_properties(send_admission_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME control_wire_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-control-wire.py"
            --receiver $<TARGET_FILE:ihs-control-wire-oracle>)
        set_tests_properties(control_wire_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME reliable_large_frame_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-reliable-large-frame.py"
            --receiver $<TARGET_FILE:ihs-reliable-large-frame-oracle>)
        set_tests_properties(reliable_large_frame_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME negotiation_stage_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-negotiation-stage.py"
            --receiver $<TARGET_FILE:ihs-negotiation-stage-oracle>)
        set_tests_properties(negotiation_stage_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME frame_events_loop_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-frame-events-loop.py"
            --receiver $<TARGET_FILE:ihs-frame-events-loop-oracle>)
        set_tests_properties(frame_events_loop_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME network_collectors_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-collectors.py"
            --receiver $<TARGET_FILE:ihs-network-collectors-oracle>)
        set_tests_properties(network_collectors_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME network_wire_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-wire.py"
            --receiver $<TARGET_FILE:ihs-network-wire-oracle>)
        set_tests_properties(network_wire_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME network_loss_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-loss.py"
            --receiver $<TARGET_FILE:ihs-network-wire-oracle>)
        set_tests_properties(network_loss_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME media_clock_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-media-clock.py"
            --receiver $<TARGET_FILE:ihs-network-wire-oracle>)
        set_tests_properties(media_clock_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME media_clock_real_workers COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-media-clock-worker.py"
            --receiver $<TARGET_FILE:ihs-early-media-worker>)
        set_tests_properties(media_clock_real_workers PROPERTIES TIMEOUT 60)
        add_test(NAME audio_start_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-audio-start.py"
            --receiver $<TARGET_FILE:ihs-audio-start-oracle>)
        set_tests_properties(audio_start_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME video_start_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-video-start.py"
            --receiver $<TARGET_FILE:ihs-video-start-oracle>)
        set_tests_properties(video_start_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME video_stop_phases_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-video-stop-phases.py"
            --receiver $<TARGET_FILE:ihs-video-stop-phases-oracle>)
        set_tests_properties(video_stop_phases_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME video_subframe_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-video-subframe.py"
            --receiver $<TARGET_FILE:ihs-video-subframe-oracle>)
        set_tests_properties(video_subframe_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME video_nal_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-video-nal.py"
            --receiver $<TARGET_FILE:ihs-video-nal-oracle>)
        set_tests_properties(video_nal_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME video_crypto_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-video-crypto.py"
            --receiver $<TARGET_FILE:ihs-video-crypto-oracle>)
        set_tests_properties(video_crypto_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME video_content_mode_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-video-content-mode.py"
            --receiver $<TARGET_FILE:ihs-video-content-mode-oracle>)
        set_tests_properties(video_content_mode_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME decoder_queue_wake_native COMMAND ihs-video-queue-oracle
            "${CMAKE_SOURCE_DIR}/app/tests/fixtures/video/sequential.h264" --wake)
        set_tests_properties(decoder_queue_wake_native PROPERTIES TIMEOUT 20)
        add_test(NAME decoder_queue_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-decoder-queue.py"
            --receiver $<TARGET_FILE:ihs-video-queue-oracle>)
        set_tests_properties(decoder_queue_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME keyframe_flush_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-keyframe-flush.py"
            --receiver $<TARGET_FILE:ihs-video-keyframe-oracle>)
        set_tests_properties(keyframe_flush_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME early_media_real_workers COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-early-media-worker.py"
            --receiver $<TARGET_FILE:ihs-early-media-worker>)
        set_tests_properties(early_media_real_workers PROPERTIES TIMEOUT 60)
        add_test(NAME early_media_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-early-media.py"
            --receiver $<TARGET_FILE:ihs-network-wire-oracle>)
        set_tests_properties(early_media_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME media_admission_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-media-admission.py"
            --receiver $<TARGET_FILE:ihs-network-wire-oracle>)
        set_tests_properties(media_admission_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME video_network_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-video-network.py"
            --receiver $<TARGET_FILE:ihs-network-wire-oracle>)
        set_tests_properties(video_network_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME media_network_stats_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-media-network-stats.py"
            --collector $<TARGET_FILE:ihs-media-network-stats-oracle>
            --receiver $<TARGET_FILE:ihs-network-wire-oracle>)
        set_tests_properties(media_network_stats_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME network_test_media_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-test-media.py"
            --receiver $<TARGET_FILE:ihs-network-wire-oracle>
            --collector $<TARGET_FILE:ihs-media-network-stats-oracle>
            --negotiator $<TARGET_FILE:nsl-auth-udp-oracle>)
        set_tests_properties(network_test_media_official_vectors PROPERTIES TIMEOUT 90)
        add_test(NAME proof_transaction_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-proof-transaction.py"
            --receiver $<TARGET_FILE:ihs-auto-authorization-oracle>)
        set_tests_properties(proof_transaction_official_vectors PROPERTIES TIMEOUT 90)
        add_test(NAME auto_authorization_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-auto-authorization.py"
            --receiver $<TARGET_FILE:ihs-auto-authorization-oracle>)
        set_tests_properties(auto_authorization_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME device_token_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-device-token.py"
            --receiver $<TARGET_FILE:ihs-device-token-oracle>)
        set_tests_properties(device_token_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME authorization_lifetime_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-authorization-lifetime.py"
            --receiver $<TARGET_FILE:ihs-authorization-exchange-oracle>)
        add_test(NAME authorization_lifetime_pump_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-authorization-lifetime.py"
            --receiver $<TARGET_FILE:ihs-authorization-exchange-oracle> --deferred)
        set_tests_properties(authorization_lifetime_official_vectors
            authorization_lifetime_pump_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME authorization_pump_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-authorization-exchange.py"
            --receiver $<TARGET_FILE:ihs-authorization-exchange-oracle> --deferred)
        set_tests_properties(authorization_pump_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME streaming_pin_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-streaming-pin.py"
            --receiver $<TARGET_FILE:ihs-streaming-pin-oracle>)
        set_tests_properties(streaming_pin_official_vectors PROPERTIES TIMEOUT 30)
        add_test(NAME authorization_exchange_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-authorization-exchange.py"
            --receiver $<TARGET_FILE:ihs-authorization-exchange-oracle>)
        set_tests_properties(authorization_exchange_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME streaming_transaction_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-streaming-transaction.py"
            --receiver $<TARGET_FILE:ihs-streaming-transaction-oracle>)
        set_tests_properties(streaming_transaction_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME network_test_connect_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-test-connect.py"
            --receiver $<TARGET_FILE:ihs-network-test-connect-oracle>)
        set_tests_properties(network_test_connect_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME network_test_lifecycle_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-test-lifecycle.py"
            --receiver $<TARGET_FILE:ihs-network-test-oracle>)
        set_tests_properties(network_test_lifecycle_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME network_test_discovery_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-test-discovery.py"
            --receiver $<TARGET_FILE:ihs-network-test-discovery-oracle>)
        set_tests_properties(network_test_discovery_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME session_key_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-session-key.py"
            --receiver $<TARGET_FILE:ihs-session-key-oracle>)
        set_tests_properties(session_key_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME connection_wait_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-connection-wait.py"
            --receiver $<TARGET_FILE:nsl-connection-wait-oracle>)
        set_tests_properties(connection_wait_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME receive_cycle_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-receive-cycle.py"
            --receiver $<TARGET_FILE:ihs-network-wire-oracle>)
        set_tests_properties(receive_cycle_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME network_cycle_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-cycle.py"
            --receiver $<TARGET_FILE:ihs-network-wire-oracle>)
        set_tests_properties(network_cycle_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME network_deadline_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-network-deadline.py"
            --receiver $<TARGET_FILE:ihs-network-wire-oracle>)
        set_tests_properties(network_deadline_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME client_shutdown_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-client-shutdown.py"
            --receiver $<TARGET_FILE:ihs-client-shutdown-oracle>)
        set_tests_properties(client_shutdown_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME control_handoff_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-control-handoff.py"
            --receiver $<TARGET_FILE:ihs-control-handoff-oracle>)
        set_tests_properties(control_handoff_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME negotiation_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-negotiation.py"
            --receiver $<TARGET_FILE:ihs-negotiation-oracle>)
        set_tests_properties(negotiation_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME reliable_channels_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-reliable-channels.py"
            --receiver $<TARGET_FILE:ihs-reliable-channels-oracle>)
        set_tests_properties(reliable_channels_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME reliable_feedback_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-reliable-feedback.py"
            --receiver $<TARGET_FILE:ihs-reliable-feedback-oracle>)
        set_tests_properties(reliable_feedback_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME initial_send_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-initial-send.py"
            --receiver $<TARGET_FILE:ihs-initial-send-oracle>)
        set_tests_properties(initial_send_official_vectors PROPERTIES TIMEOUT 60)
    endif()
endif()
