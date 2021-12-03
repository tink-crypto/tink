#!/bin/bash
# Copyright 2020 Google LLC
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

if [[ -n "${KOKORO_ROOT}" ]]; then
  cd "${KOKORO_ARTIFACTS_DIR}/git/tink"
  ./kokoro/copy_credentials.sh
fi

cd go/
use_bazel.sh "$(cat .bazelversion)"
time bazel build -- ...
time bazel test -- ...

# Run manual tests which rely on test data only available via Bazel.
if [[ -n "${KOKORO_ROOT}" ]]; then
  declare -a MANUAL_TARGETS
  MANUAL_TARGETS=(
    "//integration/gcpkms:go_default_test"
  )
  readonly MANUAL_TARGETS
  time bazel test -- "${MANUAL_TARGETS[@]}"
fi
