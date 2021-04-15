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

# The following assoicative array contains:
#   ["<Python version>"]="<python tag>-<abi tag>"
# where:
#   <Python version> = language version, e.g "3.7"
#   <python tag-<abi tag> = tags as specified in in PEP 491, e.g. "cp37-37m"
declare -A PYTHON_VERSIONS
PYTHON_VERSIONS["3.7"]="cp37-cp37m"
PYTHON_VERSIONS["3.8"]="cp38-cp38"
# TODO(ckl): Enable when macOS solution is in place.
#PYTHON_VERSIONS["3.9"]="cp39-cp39"
readonly -A PYTHON_VERSIONS

export TINK_SRC_PATH="/tmp/tink"

# Required to fix https://github.com/pypa/manylinux/issues/357.
export LD_LIBRARY_PATH="/usr/local/lib"

# This link is required on CentOS, as curl used in the AWS SDK looks for the
# certificates in this location. Removing this line will cause the AWS KMS tests
# to fail.
ln -s /etc/ssl/certs/ca-bundle.trust.crt /etc/ssl/certs/ca-certificates.crt

for v in "${!PYTHON_VERSIONS[@]}"; do
  (
    # Executing in a subshell to make the PATH modification temporary.
    export PATH="${PATH}:/opt/python/${PYTHON_VERSIONS[$v]}/bin"

    pip3 install release/*-"${PYTHON_VERSIONS[$v]}"-manylinux2014_x86_64.whl
    find tink/ -not -path "*cc/pybind*" -type f -name "*_test.py" -print0 \
      | xargs -0 -n1 python3
  )
done
