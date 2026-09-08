add_executable(switch-stream-selftest main.c)
target_link_libraries(switch-stream-selftest PRIVATE nsl_platform)
nx_create_nro(switch-stream-selftest OUTPUT switch-stream-selftest.nro)
