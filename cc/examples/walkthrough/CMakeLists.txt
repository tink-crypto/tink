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

# Library targets.

add_library(create_keyset create_keyset.cc create_keyset.h)
target_include_directories(create_keyset PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" "${TINK_EXAMPLES_WALKTHROUGH_INCLUDE_ALIAS_DIR}")
target_link_libraries(create_keyset tink::static)

add_library(load_cleartext_keyset load_cleartext_keyset.cc load_cleartext_keyset.h)
target_include_directories(load_cleartext_keyset PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" "${TINK_EXAMPLES_WALKTHROUGH_INCLUDE_ALIAS_DIR}")
target_link_libraries(load_cleartext_keyset tink::static)

add_library(load_encrypted_keyset load_encrypted_keyset.cc load_encrypted_keyset.h)
target_include_directories(load_encrypted_keyset PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" "${TINK_EXAMPLES_WALKTHROUGH_INCLUDE_ALIAS_DIR}")
target_link_libraries(load_encrypted_keyset tink::static)

# Test targets.
# NOTE: gmock and gtest_main are already exported by Tink.

add_executable(create_keyset_test create_keyset_test.cc)
add_test(NAME create_keyset_test COMMAND create_keyset_test WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
target_link_libraries(create_keyset_test create_keyset gmock gtest_main)

add_executable(load_cleartext_keyset_test load_cleartext_keyset_test.cc)
add_test(NAME load_cleartext_keyset_test COMMAND load_cleartext_keyset_test WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
target_link_libraries(load_cleartext_keyset_test load_cleartext_keyset gmock gtest_main)

add_executable(load_encrypted_keyset_test load_encrypted_keyset_test.cc)
add_test(NAME load_encrypted_keyset_test COMMAND load_encrypted_keyset_test WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
target_link_libraries(load_encrypted_keyset_test load_encrypted_keyset load_cleartext_keyset gmock gtest_main)

enable_testing()
