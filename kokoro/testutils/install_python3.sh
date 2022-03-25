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

readonly DEFAULT_PYTHON_VERSION=3.7.1

# This scripts installs Python 3 at a given version; if the version is not
# specified, DEFAULT_PYTHON_VERSION is used.
#
# NOTEs:
#   * If not running on Kokoro, this script will do nothing.
#   * This script MUST be sourced to update the environment of the calling
#     script.
#
# Usage:
#   source ./kokoro/testutils/install_python3.sh [version]

#######################################
# Install Python 3 at a given version.
# Globals:
#   DEFAULT_PYTHON_VERSION
# Arguments:
#   python_version: Python version to use; default is DEFAULT_PYTHON_VERSION.
#######################################
install_python3() {
  python_version="${1:-${DEFAULT_PYTHON_VERSION}}"
  # Update the list of Python versions.
  (
    cd /home/kbuilder/.pyenv/plugins/python-build/../..
    git pull
  )
  # Install Python.
  eval "$(pyenv init -)"
  pyenv install "${python_version}"
  pyenv global "${python_version}"
  # Debug output to check we are using the right version.
  echo "Using python3: $(which python3)"
  python3 --version
}

if [[ -n "${KOKORO_ROOT:-}" ]] ; then
  install_python3 "$@"
fi
