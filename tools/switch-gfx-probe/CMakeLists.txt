find_package(PkgConfig REQUIRED)
pkg_check_modules(SDL2 REQUIRED IMPORTED_TARGET sdl2)

add_executable(switch-gfx-sdl-official sdl_official.cpp)
target_compile_options(switch-gfx-sdl-official PRIVATE -g)
target_link_options(switch-gfx-sdl-official PRIVATE -g)
target_link_libraries(switch-gfx-sdl-official PRIVATE PkgConfig::SDL2)
nx_create_nro(switch-gfx-sdl-official OUTPUT switch-gfx-sdl-official.nro)

add_executable(switch-gfx-gl-official gl_official.cpp)
target_compile_options(switch-gfx-gl-official PRIVATE -g -fno-rtti -fno-exceptions)
target_link_options(switch-gfx-gl-official PRIVATE -g)
target_include_directories(switch-gfx-gl-official PRIVATE
    $ENV{DEVKITPRO}/portlibs/switch/include
    $ENV{DEVKITPRO}/libnx/include)
target_link_directories(switch-gfx-gl-official PRIVATE
    $ENV{DEVKITPRO}/portlibs/switch/lib
    $ENV{DEVKITPRO}/libnx/lib)
target_link_libraries(switch-gfx-gl-official PRIVATE glad EGL glapi drm_nouveau m nx)
nx_create_nro(switch-gfx-gl-official OUTPUT switch-gfx-gl-official.nro)
