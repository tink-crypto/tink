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
  # If we are running on Kokoro cd into the repository.
  if [[ -n "${KOKORO_ROOT:-}" ]]; then
    cd "${KOKORO_ARTIFACTS_DIR}/git/tink_examples"
  fi

  # Note: When running on the Kokoro CI, we expect these two folders to exist:
  #
  #  ${KOKORO_ARTIFACTS_DIR}/git/tink
  #  ${KOKORO_ARTIFACTS_DIR}/git/tink_examples
  #
  # If this is not the case, we are either using this script locally for a
  # manual on-off test (running it from the root of a local copy of the
  # tink-examples repository), and so we are going to checkout tink from
  # GitHub), or it is an error.
  if [[ ! -d ../tink ]]; then
    if [[ -n "${KOKORO_ROOT:-}" ]]; then
      # Some debug output and then fail.
      ls ../
      df -h
      exit 1
    fi
    git clone https://github.com/google/tink.git ../tink
  fi

  # Sourcing required to update callers environment.
  source ./kokoro/testutils/install_python3.sh

  if [[ -n "${KOKORO_ROOT:-}" ]]; then
    use_bazel.sh "$(cat cc/.bazelversion)"
  fi
  cp "cc/WORKSPACE" "cc/WORKSPACE.bak"
  ./kokoro/testutils/replace_http_archive_with_local_reposotory.py \
    -f "cc/WORKSPACE" \
    -t "../../tink"
  ./kokoro/testutils/run_bazel_tests.sh "cc"
  mv "cc/WORKSPACE.bak" "cc/WORKSPACE"
}

main "$@"
