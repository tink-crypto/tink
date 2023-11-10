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

# Install Bazelisk 1.17.0.
readonly BAZELISK_VERSION="1.17.0"
BAZELISK_URL="https://github.com/bazelbuild/bazelisk/releases/download/v${BAZELISK_VERSION}/bazelisk-linux-amd64"
BAZELISK_SHA256="61699e22abb2a26304edfa1376f65ad24191f94a4ffed68a58d42b6fee01e124"
if [[ "${ARCH}" == "aarch64" || "${ARCH}" == "arm64" ]]; then
  BAZELISK_URL="https://github.com/bazelbuild/bazelisk/releases/download/v${BAZELISK_VERSION}/bazelisk-linux-arm64"
  BAZELISK_SHA256="a836972b8a7c34970fb9ecc44768ece172f184c5f7e2972c80033fcdcf8c1870"
fi
readonly BAZELISK_URL
readonly BAZELISK_SHA256
curl -LsS "${BAZELISK_URL}" -o /usr/local/bin/bazelisk
echo "${BAZELISK_SHA256} /usr/local/bin/bazelisk" | sha256sum -c
chmod +x /usr/local/bin/bazelisk

# Install protoc 21.12 (python version 4.21.12). Needed for protocol buffer
# compilation.
readonly PROTOC_RELEASE_TAG="21.12"
PROTOC_URL="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_RELEASE_TAG}/protoc-${PROTOC_RELEASE_TAG}-linux-x86_64.zip"
PROTOC_SHA256="3a4c1e5f2516c639d3079b1586e703fc7bcfa2136d58bda24d1d54f949c315e8"
if [[ "${ARCH}" == "aarch64" || "${ARCH}" == "arm64" ]]; then
  PROTOC_URL="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_RELEASE_TAG}/protoc-${PROTOC_RELEASE_TAG}-linux-aarch_64.zip"
  PROTOC_SHA256="2dd17f75d66a682640b136e31848da9fb2eefe68d55303baf8b32617374f6711"
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
