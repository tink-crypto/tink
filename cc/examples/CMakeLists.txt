cmake_minimum_required(VERSION 3.8)

project(Examples CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Release)

# Import Tink as an in-tree dependency.
add_subdirectory(.. tink)

# Make sure we have bash.
find_program(BASH_PROGRAM bash)

# Include path at the base of the examples folder.
set(TINK_EXAMPLES_INCLUDE_PATH "${CMAKE_SOURCE_DIR}")

enable_testing()

add_subdirectory(aead)
add_subdirectory(mac)
add_subdirectory(util)
add_subdirectory(walkthrough)

