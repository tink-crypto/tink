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
#     [additional CMake parameters]

readonly CMAKE_PROJECT_DIR="$1"
shift 1
# Read the additional parameters if any.
readonly ADDITIONAL_CMAKE_PARAMETERS=("$@")

readonly CMAKE_PARAMETERS=(
  -DTINK_BUILD_TESTS=ON
  -DCMAKE_CXX_STANDARD=11
  "${ADDITIONAL_CMAKE_PARAMETERS[@]}"
)
readonly TINK_CMAKE_PROJECT_DIR="$(pwd)/${CMAKE_PROJECT_DIR}"
readonly CMAKE_BUILD_DIR="$(mktemp -dt cmake-build.XXXXXX)"
cd "${CMAKE_BUILD_DIR}"
cmake --version
cmake "${TINK_CMAKE_PROJECT_DIR}" "${CMAKE_PARAMETERS[@]}"
make -j"$(nproc)" all
CTEST_OUTPUT_ON_FAILURE=1 make test
