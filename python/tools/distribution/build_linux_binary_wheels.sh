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

# This script builds binary wheels of Tink for Linux based on PEP 599. It
# should be run inside a manylinux2014 Docker container to have the correct
# environment setup.

set -euo pipefail

# The following assoicative array contains:
#   ["<Python version>"]="<python tag>-<abi tag>"
# where:
#   <Python version> = language version, e.g "3.8"
#   <python tag>, <abi tag> = as defined at
#       https://packaging.python.org/en/latest/specifications/, e.g. "cp38-cp38"
declare -A PYTHON_VERSIONS
PYTHON_VERSIONS["3.8"]="cp38-cp38"
PYTHON_VERSIONS["3.9"]="cp39-cp39"
PYTHON_VERSIONS["3.10"]="cp310-cp310"
PYTHON_VERSIONS["3.11"]="cp311-cp311"
readonly -A PYTHON_VERSIONS

export TINK_PYTHON_ROOT_PATH="${PWD}"
export ARCH="$(uname -m)"

# Install Bazelisk 1.19.0.
readonly BAZELISK_VERSION="1.19.0"
BAZELISK_URL="https://github.com/bazelbuild/bazelisk/releases/download/v${BAZELISK_VERSION}/bazelisk-linux-amd64"
BAZELISK_SHA256="d28b588ac0916abd6bf02defb5433f6eddf7cba35ffa808eabb65a44aab226f7"
if [[ "${ARCH}" == "aarch64" || "${ARCH}" == "arm64" ]]; then
  BAZELISK_URL="https://github.com/bazelbuild/bazelisk/releases/download/v${BAZELISK_VERSION}/bazelisk-linux-arm64"
  BAZELISK_SHA256="861a16ba9979613e70bd3d2f9d9ab5e3b59fe79471c5753acdc9c431ab6c9d94"
fi
readonly BAZELISK_URL
readonly BAZELISK_SHA256
curl -LsS "${BAZELISK_URL}" -o /usr/local/bin/bazelisk
echo "${BAZELISK_SHA256} /usr/local/bin/bazelisk" | sha256sum -c
chmod +x /usr/local/bin/bazelisk

# Install protoc 25.1. Needed for protocol buffer compilation.
readonly PROTOC_RELEASE_TAG="25.1"
PROTOC_URL="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_RELEASE_TAG}/protoc-${PROTOC_RELEASE_TAG}-linux-x86_64.zip"
PROTOC_SHA256="ed8fca87a11c888fed329d6a59c34c7d436165f662a2c875246ddb1ac2b6dd50"
if [[ "${ARCH}" == "aarch64" || "${ARCH}" == "arm64" ]]; then
  PROTOC_URL="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_RELEASE_TAG}/protoc-${PROTOC_RELEASE_TAG}-linux-aarch_64.zip"
  PROTOC_SHA256="99975a8c11b83cd65c3e1151ae1714bf959abc0521acb659bf720524276ab0c8"
fi
readonly PROTOC_URL
readonly PROTOC_SHA256
curl -LsS "${PROTOC_URL}" -o protoc.zip
echo "${PROTOC_SHA256} protoc.zip" | sha256sum -c
unzip -o protoc.zip -d /usr/local bin/protoc

# Required to fix https://github.com/pypa/manylinux/issues/357.
export LD_LIBRARY_PATH="/usr/local/lib"

for v in "${!PYTHON_VERSIONS[@]}"; do
  (
    # Executing in a subshell to make the PATH modification temporary.
    # This makes shure that `which python3 ==
    # /opt/python/${PYTHON_VERSIONS[$v]}/bin/python3`, which is a symlink of
    # `/opt/python/${PYTHON_VERSIONS[$v]}/bin/python${v}`. This should allow
    # pybind11_bazel to pick up the correct Python binary [1].
    #
    # [1] https://github.com/pybind/pybind11_bazel/blob/fc56ce8a8b51e3dd941139d329b63ccfea1d304b/python_configure.bzl#L434
    export PATH="${PATH}:/opt/python/${PYTHON_VERSIONS[$v]}/bin"
    python3 -m pip wheel .
  )
done

# Repair wheels to convert them from linux to manylinux.
for wheel in ./tink*.whl; do
    auditwheel repair "${wheel}" -w release
done
