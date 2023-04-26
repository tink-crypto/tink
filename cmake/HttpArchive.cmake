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

include(FetchContent)
include(CMakeParseArguments)

# Download, unpack and configure a dependency.
#
# The project is added as a subdirectory of Tink, unless DATA_ONLY is
# specified. This makes all target defined by it available as dependencies.
#
# This rule also defines two variables:
#   - <NAME>_SOURCE_DIR points to the root directory of the downloaded package;
#     it can be used to reference data in tests, or append extra include/link
#     paths in the Workspace file.
#   - <NAME>_BINARY_DIR points to the build directory.
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
  FetchContent_Declare(
    ${http_archive_NAME}
    URL       ${http_archive_URL}
    URL_HASH  SHA256=${http_archive_SHA256}
  )
  message(STATUS "Fetching ${http_archive_NAME}")
  FetchContent_GetProperties(${http_archive_NAME})
  if(NOT ${http_archive_NAME}_POPULATED)
    FetchContent_Populate(${http_archive_NAME})
    if (NOT http_archive_DATA_ONLY)
      add_subdirectory(
        ${${http_archive_NAME}_SOURCE_DIR}/${http_archive_CMAKE_SUBDIR}
        ${${http_archive_NAME}_BINARY_DIR}
        EXCLUDE_FROM_ALL)
    endif()
    # Expose these variables to the caller.
    set(
      "${http_archive_NAME}_SOURCE_DIR"
      "${${http_archive_NAME}_SOURCE_DIR}"
      PARENT_SCOPE)
    set(
      "${http_archive_NAME}_BINARY_DIR"
      "${${http_archive_NAME}_BINARY_DIR}"
      PARENT_SCOPE)
  endif()
endfunction(http_archive)
