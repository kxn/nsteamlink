cmake_minimum_required(VERSION 3.22)
project(nsl_protobuf_runtime C)
# D-007: upstream's CMake requires host C++ Protobuf even with codegen off.
add_library(protobuf-c STATIC "${PROTOBUF_SOURCE}/protobuf-c/protobuf-c.c")
target_include_directories(protobuf-c PRIVATE "${PROTOBUF_SOURCE}")
install(TARGETS protobuf-c ARCHIVE DESTINATION lib)
install(FILES "${PROTOBUF_SOURCE}/protobuf-c/protobuf-c.h" DESTINATION include/protobuf-c)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/libprotobuf-c.pc"
    "prefix=${CMAKE_INSTALL_PREFIX}\nlibdir=\${prefix}/lib\nincludedir=\${prefix}/include\nName: libprotobuf-c\nDescription: protobuf-c runtime\nVersion: 1.5.0\nLibs: -L\${libdir} -lprotobuf-c\nCflags: -I\${includedir}\n")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libprotobuf-c.pc" DESTINATION lib/pkgconfig)
