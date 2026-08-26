# M2 探针：Switch 上的 IHSlib 主机发现验证工具（仅 Switch 目标构建）
if(NOT TARGET ihslib)
    add_subdirectory(${CMAKE_SOURCE_DIR}/third_party/ihslib ${CMAKE_CURRENT_BINARY_DIR}/ihslib-build)
endif()

add_executable(switch-discover main.c)
target_include_directories(switch-discover PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/client
    ${CMAKE_SOURCE_DIR}/third_party/ihslib/src/protobuf
    $ENV{DEVKITPRO}/portlibs/switch/include)
target_compile_options(switch-discover PRIVATE -g)
target_link_options(switch-discover PRIVATE -g)
target_link_libraries(switch-discover PRIVATE ihslib nx)
nx_create_nro(switch-discover OUTPUT switch-discover.nro)
