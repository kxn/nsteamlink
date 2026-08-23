# M2 探针：Switch 上的 IHSlib 主机发现验证工具（仅 Switch 目标构建）
add_subdirectory(${CMAKE_SOURCE_DIR}/third_party/ihslib ${CMAKE_CURRENT_BINARY_DIR}/ihslib-build)

add_executable(switch-discover main.c)
target_link_libraries(switch-discover PRIVATE ihslib nx)
nx_create_nro(switch-discover OUTPUT switch-discover.nro)
