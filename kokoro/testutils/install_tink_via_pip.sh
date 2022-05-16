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

# This scripts installs Tink for Python and its dependencies using Pip.
# Tink's root folder must be specified.
#
# NOTES:
#   * If not running on Kokoro, this script will do nothing.
#   * This script MUST be sourced to update the environment of the calling
#     script.
#   * The required Bazel version *must* be installed before running this script
#     with:
#       use_bazel.sh "$(cat <path to version file>/.bazelversion)"
#
# Usage:
#   source ./kokoro/testutils/install_tink_via_pip.sh <path to tink root>

install_tink_via_pip() {
  local tink_root_path="${1}"
  # Keep track of the current directory to cd back to it later.
  readonly local current_dir="${PWD}"
  cd "${tink_root_path}"
  readonly local platform="$(uname | tr '[:upper:]' '[:lower:]')"
  local -a pip_flags
  if [[ "${platform}" == 'darwin' ]]; then
    pip_flags=( --user )
  fi
  readonly pip_flags

  # Set path to Tink base folder.
  export TINK_PYTHON_SETUPTOOLS_OVERRIDE_BASE_PATH="${PWD}"

  # Temporary disable treating unset variables generating errors to avoid old
  # versions of bash generating errors when expanding empty pip_flags array.
  set +u
  # Check if we can build Tink python package.
  pip3 install "${pip_flags[@]}" --upgrade pip
  # TODO(b/219813176): Remove once Kokoro environment is compatible.
  pip3 install "${pip_flags[@]}" --upgrade 'setuptools==60.9.0'
  pip3 install "${pip_flags[@]}" ./python
  # Install dependencies for the examples/python tests
  pip3 install "${pip_flags[@]}" google-cloud-storage
  set -u
  cd "${current_dir}"
}

if [[ -n "${KOKORO_ROOT:-}" ]] ; then
  if (( "$#" < 1 )); then
    echo "Tink root path must be specified" >&2
    exit 1
  fi
  install_tink_via_pip "$@"
fi
