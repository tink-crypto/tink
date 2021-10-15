#!/bin/bash

# Copyright 2021 Google LLC
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

set -e

# Install libssl-dev only when running in Kokoro to allow running the script
# locally for debugging purposes.
if [[ -n "${KOKORO_ROOT}" ]]; then
  # Install the latest version of OpenSSL.
  sudo apt-get install libssl-dev -y
fi

cd git*/tink

./kokoro/copy_credentials.sh

# Currently there is a limited list of targets that can be built with OpenSSL.
# This list is expected to grow larger as new targets can use OpenSSL.
TEST_TARGETS=(
  "tink_test_subtle_random_test"
  "tink_test_subtle_aes_cmac_boringssl_test"
  "tink_test_subtle_aes_gcm_boringssl_test"
)

echo "========================================================= Running cmake"
cmake --version
cmake . \
  -DTINK_BUILD_TESTS=ON \
  -DCMAKE_CXX_STANDARD=11 \
  -DTINK_USE_SYSTEM_OPENSSL=ON
echo "==================================================== Building with make"
make -j "$(nproc)" "${TEST_TARGETS[@]}"
echo "======================================================= Testing targets"
for target in "${TEST_TARGETS[@]}"; do
  ./cc/subtle/"${target}"
done
echo "================================================== Done testing targets"
