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

CURRENT_BAZEL_VERSION=""

use_bazel() {
  local candidate_version="$1"
  if [[ "${candidate_version}" != "${CURRENT_BAZEL_VERSION}" ]]; then
    CURRENT_BAZEL_VERSION="${candidate_version}"
    if [[ -n "${KOKORO_ROOT:-}" ]] ; then
      use_bazel.sh "${candidate_version}"
    else
      bazel --version
    fi
  fi
}

main() {
  if [[ -n "${KOKORO_ROOT:-}" ]] ; then
    cd "${KOKORO_ARTIFACTS_DIR}/git/tink"
    ./kokoro/testutils/copy_credentials.sh "testdata"
    ./kokoro/testutils/update_android_sdk.sh
    # Sourcing required to update callers environment.
    source ./kokoro/testutils/install_python3.sh
    source ./kokoro/testutils/install_go.sh
  fi
  (
    cd testing/cc
    use_bazel "$(cat .bazelversion)"
    time bazel build -- ...
    time bazel test --test_output=errors -- ...
  )
  (
    cd testing/go
    use_bazel "$(cat .bazelversion)"
    time bazel build -- ...
    time bazel test --test_output=errors -- ...
  )
  (
    cd testing/java_src
    use_bazel "$(cat .bazelversion)"
    time bazel build -- ...
    time bazel build :testing_server_deploy.jar
    time bazel test --test_output=errors -- ...
  )
  (
    cd testing/python
    use_bazel "$(cat .bazelversion)"
    time bazel build -- ...
    time bazel test --test_output=errors -- ...
  )

  local TINK_SRC_PATH="${PWD}"
  (
    cd testing/cross_language
    use_bazel "$(cat .bazelversion)"
    time bazel test \
      --test_env TINK_SRC_PATH="${TINK_SRC_PATH}" --test_output=errors -- ...
  )
}

main "$@"
