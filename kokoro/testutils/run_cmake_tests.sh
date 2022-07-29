#!/bin/bash
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

# This script builds with CMake and runs tests within a given directory.
#
# Users must spcify the CMake project directory. Optionally, users may specify
# a list of additional CMake arguments.
#
# Usage:
#   ./kokoro/testutils/run_cmake_tests.sh \
#     <project directory> \
#     [<additional CMake param> <additional CMake param> ...]

set -eEo pipefail

usage() {
  echo "Usage: $0 <project directory> \\"
  echo "         [<additional CMake param> <additional CMake param> ...]"
  exit 1
}

CMAKE_PROJECT_DIR=
ADDITIONAL_CMAKE_PARAMETERS=

#######################################
# Process command line arguments.
#
# Globals:
#   PROJECT_DIRECTORY
#
#######################################
process_args() {
  CMAKE_PROJECT_DIR="$1"
  readonly CMAKE_PROJECT_DIR

  if [[ -z "${CMAKE_PROJECT_DIR}" ]]; then
    usage
  fi

  shift 1
  ADDITIONAL_CMAKE_PARAMETERS=("$@")
  readonly ADDITIONAL_CMAKE_PARAMETERS
}

main() {
  process_args "$@"
  local -r cmake_parameters=(
    -DTINK_BUILD_TESTS=ON
    -DCMAKE_CXX_STANDARD=11
    "${ADDITIONAL_CMAKE_PARAMETERS[@]}"
  )
  # We need an absolute path to the CMake project directory.
  local -r tink_cmake_project_dir="$(pwd)/$(basename ${CMAKE_PROJECT_DIR})"
  local -r cmake_build_dir="$(mktemp -dt cmake-build.XXXXXX)"
  cd "${cmake_build_dir}"
  cmake --version
  cmake "${tink_cmake_project_dir}" "${cmake_parameters[@]}"
  make -j"$(nproc)" all
  CTEST_OUTPUT_ON_FAILURE=1 make test
}

main "$@"
