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
cd ${KOKORO_ARTIFACTS_DIR}/git/tink

./kokoro/copy_credentials.sh

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

run_bazel_tests() {
  (
    cd python
    use_bazel.sh $(cat .bazelversion)

    time bazel build -- ...
    time bazel test --test_output=errors -- ...

    # Run manual tests which rely on key material injected into the Kokoro
    # environement.
    if [[ -n "${KOKORO_ROOT}" ]]; then
      declare -a MANUAL_TARGETS
      MANUAL_TARGETS=(
        "//tink/integration/gcpkms:_gcp_kms_aead_test"
      )
      readonly MANUAL_TARGETS
      time bazel test --test_output=errors -- "${MANUAL_TARGETS[@]}"
    fi
  )
}

install_python3
run_bazel_tests
