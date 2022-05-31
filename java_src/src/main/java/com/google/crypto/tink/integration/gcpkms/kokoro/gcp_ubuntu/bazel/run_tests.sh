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


# Note: When running on the Kokoro CI, we expect these two folders to exist:
#
#  ${KOKORO_ARTIFACTS_DIR}/git/tink_java
#  ${KOKORO_ARTIFACTS_DIR}/git/tink_java_gcpkms
#
# If running locally make sure ../tink_java exists.
if [[ -n "${KOKORO_ROOT:-}" ]] ; then
  cd "${KOKORO_ARTIFACTS_DIR}/git/tink_java_gcpkms"
  use_bazel.sh "$(cat .bazelversion)"
fi

./kokoro/testutils/copy_credentials.sh "testdata"
./kokoro/testutils/update_android_sdk.sh
./kokoro/testutils/run_bazel_tests.sh .
