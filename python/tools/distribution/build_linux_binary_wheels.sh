#!/bin/bash
# This script builds binary wheels of Tink for Linux based on PEP 599. It
# should be run inside a manylinux2014 Docker container to have the correct
# environment setup.

set -euo pipefail

# Get dependencies which are needed for building Tink
# Install Bazel which is needed for building C++ extensions
BAZEL_VERSION='3.1.0'
curl -OL https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
chmod +x bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
./bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh

# Install Protoc which is needed for compiling the protos
PROTOC_ZIP='protoc-3.11.4-linux-x86_64.zip'
curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v3.11.4/${PROTOC_ZIP}
unzip -o "${PROTOC_ZIP}" -d /usr/local bin/protoc

# Setup required for Tink
export TINK_PYTHON_SETUPTOOLS_OVERRIDE_BASE_PATH=/tmp/tink

# Build wheel for Python 3.7
(
  # Set Path to Python3.7
  export PATH=$PATH:/opt/python/cp37-cp37m/bin

  # Create binary wheel
  pip wheel .
)

# This is needed to ensure we get a clean build, as otherwise parts of the
# Python 3.8 package use compiled code for Python 3.7.
bazel clean --expunge

# Build wheel for Python 3.8
(
  # Set Path to Python3.8
  export PATH=$PATH:/opt/python/cp38-cp38/bin

  # Create binary wheel
  pip wheel .
)

# Repair wheels to convert them from linux to manylinux.
for wheel in ./tink*.whl; do
    auditwheel repair "$wheel" -w release
done
