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

./kokoro/testutils/update_certs.sh
# Only installing CMake; OpenSSL is installed by the example script.
source ./kokoro/testutils/install_cmake.sh

export TEST_TMPDIR="$(mktemp -dt examples-cc-cmake-openssl.XXXXXX)"
export TEST_SRCDIR="$(cd ..; pwd)"
cd examples/cc/helloworld
./cmake_build_test.sh --openssl
