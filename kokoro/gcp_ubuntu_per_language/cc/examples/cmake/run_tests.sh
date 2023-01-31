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

# Sourcing is needed to update the caller environment.
# Install CMake 3.10 which is the minimum required.
source ./kokoro/testutils/install_cmake.sh "3.10.0" \
  "6b5ea290042fac96023fd5387cd65cc69fdf4f48bad91177eb8697ba37e3deb3"

./kokoro/testutils/run_cmake_tests.sh "cc/examples" -DTINK_BUILD_TESTS=OFF

