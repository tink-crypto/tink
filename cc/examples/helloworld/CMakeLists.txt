cmake_minimum_required(VERSION 3.8)
project(TinkHelloWorld CXX)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Release)

# Import Tink as an in-tree dependency.
add_subdirectory(../../.. tink)

add_executable(hello_world hello_world.cc)
target_link_libraries(hello_world tink::static)
