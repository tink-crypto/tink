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

set -euo pipefail

if [[ -n "${KOKORO_ROOT:-}" ]]; then
  cd "${KOKORO_ARTIFACTS_DIR}/git/tink"
fi

./kokoro/testutils/upgrade_gcc.sh
# Sourcing is needed to update the caller environment.
# Install CMake 3.13 which is the minimum required.
source ./kokoro/testutils/install_cmake.sh "3.13.5" \
  "e2fd0080a6f0fc1ec84647acdcd8e0b4019770f48d83509e6a5b0b6ea27e5864"

./kokoro/testutils/run_cmake_tests.sh "cc/examples" -DTINK_BUILD_TESTS=OFF

