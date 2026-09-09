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
add_library(nsl_video_contracts STATIC platforms/common/frame_lifetime.c platforms/common/app_lifecycle.c)
target_include_directories(nsl_video_contracts PUBLIC platforms/common)
target_compile_options(nsl_video_contracts PRIVATE -Wall -Wextra)
add_library(nsl_video_pipeline STATIC platforms/common/video_pipeline.c)
target_include_directories(nsl_video_pipeline PUBLIC platforms/common)
target_compile_options(nsl_video_pipeline PRIVATE -Wall -Wextra -Wno-unknown-pragmas)
target_link_libraries(nsl_video_pipeline PUBLIC nsl_video_contracts ihslib PkgConfig::FFMPEG Threads::Threads)
set(NSL_GFX_BACKEND "sdl" CACHE STRING "Graphics backend: sdl or deko (Switch only)")
set_property(CACHE NSL_GFX_BACKEND PROPERTY STRINGS sdl deko)
if(NOT NSL_GFX_BACKEND STREQUAL "sdl" AND NOT NSL_GFX_BACKEND STREQUAL "deko")
    message(FATAL_ERROR "Unsupported graphics backend: ${NSL_GFX_BACKEND}")
endif()
add_library(nsl_gfx STATIC platforms/common/gfx_common.c)
if(NSL_GFX_BACKEND STREQUAL "deko")
    if(NOT NSL_PLATFORM STREQUAL "switch")
        message(FATAL_ERROR "deko backend requires the Switch toolchain")
    endif()
    find_program(NSL_UAM uam HINTS /opt/devkitpro/tools/bin NO_CMAKE_FIND_ROOT_PATH REQUIRED)
    if(NSL_DIAGNOSTICS)
        find_library(NSL_DEKO3D_DEBUG deko3dd REQUIRED)
        set(NSL_DEKO3D "${NSL_DEKO3D_DEBUG}")
    else()
        find_library(NSL_DEKO3D deko3d REQUIRED)
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
add_library(nsl_ui STATIC src/ui/ui_model.c src/ui/ui_layout.c src/ui/ui_events.c src/input/input_router.c
    src/services/host_registry.c src/services/auth_store.c src/services/i18n.c)
target_include_directories(nsl_ui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(nsl_ui PRIVATE -Wall -Wextra)
target_link_libraries(nsl_ui PUBLIC m)
add_dependencies(nsl_ui nsl_identity nsl_i18n)
target_include_directories(nsl_ui PUBLIC ${NSL_IDENTITY_DIR} ${NSL_I18N_DIR})
target_compile_definitions(nsl_ui PUBLIC NSL_DIAGNOSTICS=$<BOOL:${NSL_DIAGNOSTICS}>)
add_library(nsl_platform STATIC platforms/common/application.c platforms/common/sdl_input.c platforms/common/media.c
    platforms/common/shortcut_package.c platforms/${NSL_PLATFORM}/shortcut.c
    platforms/common/ui_renderer.c platforms/common/ui_audio.c platforms/common/runtime.c platforms/${NSL_PLATFORM}/system.c
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
target_link_libraries(nsl_platform PUBLIC nsl_ui nsl_artwork ihslib ihslib-hid-sdl PkgConfig::SDL2 PkgConfig::SDL2_TTF
    PkgConfig::FFMPEG PkgConfig::OPUS Threads::Threads nsl_gfx)
add_executable(nsteamlink src/main.c)
target_link_libraries(nsteamlink PRIVATE nsl_platform)
if(NSL_PLATFORM STREQUAL "switch")
    target_sources(nsl_platform PRIVATE platforms/switch/rumble.c platforms/switch/preflight.c)
    target_link_options(nsl_platform INTERFACE -Wl,--wrap=SDL_GameControllerRumble)
    target_link_libraries(nsl_platform PUBLIC nx)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(NSL_NACP "${CMAKE_CURRENT_BINARY_DIR}/control.nacp")
    set(NSL_KEYSET "" CACHE FILEPATH "Local Switch keyset; never commit it")
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
    add_custom_target(nsteamlink_nsp
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/scripts/package-switch.py"
            --elf "$<TARGET_FILE:nsteamlink>" --nacp "${NSL_NACP}"
            --icon "${CMAKE_SOURCE_DIR}/assets/branding/icon.jpg"
            --config "${CMAKE_SOURCE_DIR}/packaging/switch/application.json"
            --output "${CMAKE_CURRENT_BINARY_DIR}/nsteamlink.nsp"
            --keyset "${NSL_KEYSET}" --hacbrewpack "${HACBREWPACK}"
        DEPENDS nsteamlink "${NSL_NACP}" VERBATIM)
    add_custom_target(nsteamlink_release DEPENDS nsteamlink_nro nsteamlink_nsp)
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
    target_link_libraries(nsl-preflight-tests PRIVATE nsl_ui)
    target_compile_options(nsl-preflight-tests PRIVATE -Wall -Wextra -UNDEBUG)
    add_test(NAME nsl-preflight COMMAND nsl-preflight-tests)
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

if(NSL_PLATFORM STREQUAL "switch" AND NSL_GFX_BACKEND STREQUAL "deko" AND NSL_DIAGNOSTICS)
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
    DEPENDS nsl_gfx "${CMAKE_SOURCE_DIR}/scripts/graphics-manifest.py" VERBATIM)
