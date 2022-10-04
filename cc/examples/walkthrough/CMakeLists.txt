cmake_minimum_required(VERSION 3.8)

project(WalkthroughExamples CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Release)

# Import Tink as an in-tree dependency.
add_subdirectory(../.. tink)

# Create an alias to allow including headers as walkthrough/*.h
set(TINK_EXAMPLES_WALKTHROUGH_INCLUDE_ALIAS_DIR "${CMAKE_CURRENT_BINARY_DIR}/__include_alias")
get_filename_component(_destination_parent "${TINK_EXAMPLES_WALKTHROUGH_INCLUDE_ALIAS_DIR}/walkthrough" DIRECTORY)
file(MAKE_DIRECTORY "${_destination_parent}")
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink "${CMAKE_CURRENT_SOURCE_DIR}" "${TINK_EXAMPLES_WALKTHROUGH_INCLUDE_ALIAS_DIR}/walkthrough")

# Library target create_keyset.
add_library(create_keyset create_keyset.cc create_keyset.h)
target_include_directories(create_keyset PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" "${TINK_EXAMPLES_WALKTHROUGH_INCLUDE_ALIAS_DIR}")
target_link_libraries(create_keyset tink::static)

# NOTE: gmock and gtest_main are already exported by Tink.
add_executable(create_keyset_test create_keyset_test.cc)
add_test(NAME create_keyset_test COMMAND create_keyset_test WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
target_link_libraries(create_keyset_test create_keyset gmock gtest_main)

enable_testing()
