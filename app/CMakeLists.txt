find_package(PkgConfig REQUIRED)
pkg_check_modules(SDL2 REQUIRED IMPORTED_TARGET sdl2)
pkg_check_modules(SDL2_TTF REQUIRED IMPORTED_TARGET SDL2_ttf)
pkg_check_modules(FFMPEG REQUIRED IMPORTED_TARGET libavcodec libavutil libswscale)
pkg_check_modules(OPUS REQUIRED IMPORTED_TARGET opus)
pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)
pkg_check_modules(JPEG REQUIRED IMPORTED_TARGET libjpeg)
find_package(Threads REQUIRED)
add_library(nsl_artwork STATIC platforms/common/artwork.c platforms/common/artwork_format.c)
target_include_directories(nsl_artwork PRIVATE ${CMAKE_SOURCE_DIR}/third_party/jsmn)
target_compile_options(nsl_artwork PRIVATE -Wall -Wextra)
target_link_libraries(nsl_artwork PUBLIC nsl_ui PkgConfig::CURL PkgConfig::JPEG Threads::Threads m)
add_library(nsl_ui STATIC src/ui/ui_model.c src/ui/ui_layout.c src/ui/ui_events.c src/input/input_router.c
    src/services/host_registry.c src/services/auth_store.c)
target_include_directories(nsl_ui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(nsl_ui PRIVATE -Wall -Wextra)
target_link_libraries(nsl_ui PUBLIC m)
add_dependencies(nsl_ui nsl_identity)
target_include_directories(nsl_ui PUBLIC ${NSL_IDENTITY_DIR})
target_compile_definitions(nsl_ui PUBLIC NSL_DIAGNOSTICS=$<BOOL:${NSL_DIAGNOSTICS}>)
add_library(nsl_platform STATIC platforms/common/application.c platforms/common/sdl_input.c platforms/common/media.c
    platforms/common/ui_renderer.c platforms/common/runtime.c platforms/${NSL_PLATFORM}/system.c)
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
    PkgConfig::FFMPEG PkgConfig::OPUS Threads::Threads)
add_executable(nsteamlink src/main.c)
target_link_libraries(nsteamlink PRIVATE nsl_platform)
if(NSL_PLATFORM STREQUAL "switch")
    target_link_libraries(nsl_platform PUBLIC nx)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(NSL_NACP "${CMAKE_CURRENT_BINARY_DIR}/control.nacp")
    set(NSL_KEYSET "" CACHE FILEPATH "Local Switch keyset; never commit it")
    set(HACBREWPACK "hacbrewpack" CACHE STRING "hacBrewPack executable")
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
    add_test(NAME nsl-native COMMAND nsl-native-tests)
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
