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

main() {
  if [[ -n "${KOKORO_ROOT:-}" ]]; then
    cd "${KOKORO_ARTIFACTS_DIR}/git/tink"
  fi

  ./kokoro/testutils/copy_credentials.sh

  cd javascript
  if [[ -n "${KOKORO_ROOT:-}" ]]; then
    use_bazel.sh "$(cat .bazelversion)"
  fi

  local readonly TEST_FLAGS=(
    --strategy=TestRunner=standalone
    --test_output=errors
  )

  # This is needed to handle recent Chrome distributions on macOS which have
  # paths with spaces. Context:
  # https://github.com/bazelbuild/bazel/issues/4327#issuecomment-627422865
  local readonly BAZEL_FLAGS=( --experimental_inprocess_symlink_creation )
  bazel build "${BAZEL_FLAGS[@]}" -- ...
  bazel test "${BAZEL_FLAGS[@]}" "${TEST_FLAGS[@]}" -- ...
}

main "$@"
