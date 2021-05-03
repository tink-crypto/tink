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
cd "${KOKORO_ARTIFACTS_DIR}/git/tink"

./kokoro/copy_credentials.sh

cd python

install_python3() {
  : "${PYTHON_VERSION:=3.7.1}"

  # Update python version list.
  (
    cd /home/kbuilder/.pyenv/plugins/python-build/../..
    git pull
  )
  # Install Python.
  eval "$(pyenv init -)"
  pyenv install -v "${PYTHON_VERSION}"
  pyenv global "${PYTHON_VERSION}"
}

install_temp_protoc() {
  local protoc_version='3.14.0'
  local protoc_zip="protoc-${protoc_version}-linux-x86_64.zip"
  local protoc_url="https://github.com/protocolbuffers/protobuf/releases/download/v${protoc_version}/${protoc_zip}"
  local -r protoc_tmpdir="$(mktemp -dt tink-protoc.XXXXXX)"
  (
    cd "${protoc_tmpdir}"
    curl -OL "${protoc_url}"
    unzip "${protoc_zip}" bin/protoc
  )
  export PATH="${protoc_tmpdir}/bin:${PATH}"
}

install_pip_package() {
  # Check if we can build Tink python package.

  # Needed for setuptools
  use_bazel.sh "$(cat .bazelversion)"

  # Set path to Tink base folder
  export TINK_PYTHON_SETUPTOOLS_OVERRIDE_BASE_PATH="${PWD}/.."

  # Update pip and start setup
  pip3 install --upgrade pip
  pip3 install --upgrade setuptools
  pip3 install .
}

run_tests_with_package() {
  # Set path to Tink base folder
  export TINK_SRC_PATH="${PWD}/.."

  # Run Python tests directly so the package is used.
  # We exclude tests in tink/cc/pybind: they are implementation details and may
  # depend on a testonly shared object.
  find tink/ -not -path "*cc/pybind*" -type f -name "*_test.py" -print0 | xargs -0 -n1 python3
}

install_python3
install_temp_protoc
install_pip_package
run_tests_with_package

# Generate release of the pip package and test it
./tools/distribution/create_release.sh
