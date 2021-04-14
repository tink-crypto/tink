# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

include(ExternalProject)
include(CMakeParseArguments)

if (NOT DEFINED TINK_THIRD_PARTY_DIR)
  set(TINK_THIRD_PARTY_DIR "${CMAKE_CURRENT_BINARY_DIR}/__third_party")
endif()

# Download, unpack and configure a dependency.
#
# The project is added as a subdirectory of Tink, unless DATA_ONLY is
# specified. This makes all target defined by it available as dependencies.
#
# This rule also defines a <NAME>_SOURCE_DIR variable, which points to the
# root directory of the downloaded package and can be used to reference data in
# tests, or append extra include/link paths in the Workspace file.
#
# Parameters:
#   NAME name of the dependency.
#   URL url to fetch a source archive from.
#   SHA256 hash of the file downloaded from URL.
#
# Optional parameters:
#   CMAKE_SUBDIR subdirectory of the downloaded archive where the root
#     CMakeLists.txt file for the project is located. Defaults to the root.
#   CMAKE_ARGS any additional argument that should be passed to cmake when
#     configuring the downloaded archive. Defaults to empty.
#   DATA_ONLY flag, if present the package will only be downloaded, verified and
#     unpacked. No configuration step is performed, and no target included. This
#     is useful for downloading archives of test vectors or artifacts.
#     False by default.
#
function(http_archive)
  cmake_parse_arguments(PARSE_ARGV 0 http_archive
    "DATA_ONLY"
    "NAME;URL;SHA256;CMAKE_SUBDIR"
    "CMAKE_ARGS"
  )

  message(STATUS "Fetching ${http_archive_NAME}")

  set(http_archive_PREFIX "${TINK_THIRD_PARTY_DIR}/${http_archive_NAME}")
  set(http_archive_SOURCE_DIR "${http_archive_PREFIX}/src")
  set(http_archive_BINARY_DIR "${http_archive_PREFIX}/build")

  configure_file(
    cmake/HttpArchiveDownloader.cmake.in
    "${http_archive_PREFIX}/CMakeLists.txt")

  execute_process(
    COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
    RESULT_VARIABLE errors
    WORKING_DIRECTORY "${http_archive_PREFIX}")

  if (errors)
    message(FATAL_ERROR "While configuring ${http_archive_NAME}: ${errors}")
  endif()

  set(${http_archive_NAME}_SOURCE_DIR "${http_archive_SOURCE_DIR}" PARENT_SCOPE)

  execute_process(
    COMMAND ${CMAKE_COMMAND} --build .
    RESULT_VARIABLE errors
    WORKING_DIRECTORY "${http_archive_PREFIX}")

  if (errors)
    message(FATAL_ERROR "While fetching ${http_archive_NAME}: ${errors}")
  endif()

  if (NOT http_archive_DATA_ONLY)
    add_subdirectory(
      "${http_archive_SOURCE_DIR}/${http_archive_CMAKE_SUBDIR}"
      "${http_archive_BINARY_DIR}" EXCLUDE_FROM_ALL)
  endif()
endfunction(http_archive)
