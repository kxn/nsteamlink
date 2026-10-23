cmake_minimum_required(VERSION 3.22)

project(nsteamlink
    VERSION 0.7.0
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
# SDK diagnostics follow the application profile, including cached builds.
set(IHSLIB_DIAGNOSTICS ${NSL_DIAGNOSTICS} CACHE BOOL "Compile IHS diagnostic collection" FORCE)
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
        target_sources(GameNetworkingSockets_s PRIVATE app/platforms/switch/gns_libnx.cpp
            app/platforms/common/gns_wake_pair.cpp)
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
    if(TARGET ihs-fec-oracle)
        find_package(Python3 COMPONENTS Interpreter REQUIRED)
        add_test(NAME udp_receive_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-udp-receive.py"
            --receiver $<TARGET_FILE:ihs-udp-receive-oracle>
            --output "${CMAKE_BINARY_DIR}/udp-receive-native.json")
        set_tests_properties(udp_receive_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME fec_resources_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-fec-resources.py"
            --receiver $<TARGET_FILE:ihs-fec-resource-oracle>
            --output "${CMAKE_BINARY_DIR}/fec-resources-native.json")
        set_tests_properties(fec_resources_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME media_allocation_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-media-allocation.py"
            --receiver $<TARGET_FILE:ihs-media-budget-oracle>)
        set_tests_properties(media_allocation_official_vectors PROPERTIES TIMEOUT 60)
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
        add_test(NAME hid_producer_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-hid-producer.py"
            --receiver $<TARGET_FILE:ihs-hid-producer-oracle>)
        set_tests_properties(hid_producer_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME hid_disabled_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-hid-disabled.py"
            --receiver $<TARGET_FILE:ihs-hid-disabled-oracle>)
        set_tests_properties(hid_disabled_official_vectors PROPERTIES TIMEOUT 60)
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
        add_test(NAME video_overflow_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-video-overflow.py"
            --receiver $<TARGET_FILE:ihs-video-overflow-oracle>)
        set_tests_properties(video_overflow_official_vectors PROPERTIES TIMEOUT 30)
        add_test(NAME wait_clock_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-wait-clock.py"
            --receiver $<TARGET_FILE:ihs-thread-clock-oracle>)
        set_tests_properties(wait_clock_official_vectors PROPERTIES TIMEOUT 15)
        add_test(NAME decoder_overlap_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-decoder-overlap.py"
            --receiver $<TARGET_FILE:ihs-video-overlap-oracle>)
        set_tests_properties(decoder_overlap_official_vectors PROPERTIES TIMEOUT 90)
        add_test(NAME capacity_recovery_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-capacity-recovery.py"
            --receiver $<TARGET_FILE:ihs-video-overlap-oracle>
            --output "${CMAKE_BINARY_DIR}/steam-capacity-native.json")
        set_tests_properties(capacity_recovery_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME decoder_identity_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-decoder-identity.py"
            --receiver $<TARGET_FILE:ihs-video-identity-oracle>
            --stats-receiver $<TARGET_FILE:ihs-frame-stats-oracle>)
        set_tests_properties(decoder_identity_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME decoder_pressure_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-decoder-pressure.py"
            --receiver $<TARGET_FILE:ihs-video-pressure-oracle>
            --reuse-receiver $<TARGET_FILE:ihs-frame-reuse-oracle>
            --stats-receiver $<TARGET_FILE:ihs-frame-stats-oracle>)
        set_tests_properties(decoder_pressure_official_vectors PROPERTIES TIMEOUT 60)
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
        add_test(NAME discovery_update_order_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-discovery-order.py"
            --receiver $<TARGET_FILE:ihs-auto-authorization-oracle>)
        set_tests_properties(discovery_update_order_official_vectors PROPERTIES TIMEOUT 30)
        add_test(NAME auto_authorization_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-auto-authorization.py"
            --receiver $<TARGET_FILE:ihs-auto-authorization-oracle>)
        set_tests_properties(auto_authorization_official_vectors PROPERTIES TIMEOUT 60)
        add_test(NAME authorization_admission_official_vectors COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/check-steam-authorization-admission.py"
            --receiver $<TARGET_FILE:ihs-auto-authorization-oracle>)
        set_tests_properties(authorization_admission_official_vectors PROPERTIES TIMEOUT 60)
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
