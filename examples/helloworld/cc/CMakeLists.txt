# 3.5 is the minimum version supported by Tink and its dependencies.
cmake_minimum_required(VERSION 3.5)
project(TinkHelloWorld CXX)

set(CMAKE_BUILD_TYPE Release)
set(TINK_ENABLE_TESTS false)

# Import Tink as an in-tree dependency.
add_subdirectory(../../.. "${CMAKE_CURRENT_BINARY_DIR}/tink")

add_executable(hello_world hello_world.cc)

target_link_libraries(hello_world
  tink
  tink::core::cleartext_keyset_handle
  tink::config::tink_config
  tink::util::status
)
