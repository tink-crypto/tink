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

install_python3() {
  : "${PYTHON_VERSION:=3.7.1}"

  # Update python version list.
  (
    cd /home/kbuilder/.pyenv/plugins/python-build/../..
    git pull
    # TODO(b/187879867): Remove once pyenv issue is resolved.
    git checkout 783870759566a77d09b426e0305bc0993a522765
  )
  # Install Python.
  eval "$(pyenv init -)"
  pyenv install "${PYTHON_VERSION}"
  pyenv global "${PYTHON_VERSION}"
}

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
    install_python3
    cd "${KOKORO_ARTIFACTS_DIR}/git/tink"
    ./kokoro/copy_credentials.sh
    ./kokoro/update_android_sdk.sh
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
