#!/bin/bash

set -euo pipefail
cd ${KOKORO_ARTIFACTS_DIR}/git/tink


install_pip_package() {
  # Check if we can build Tink python package.
  (
    cd python
    # Needed for setuptools

    use_bazel.sh $(cat .bazelversion)
    # Install the proto compiler
    PROTOC_ZIP=protoc-3.11.4-osx-x86_64.zip
    curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v3.11.4/$PROTOC_ZIP
    sudo unzip -o $PROTOC_ZIP -d /usr/local bin/protoc
    # Update pip and install all requirements. Note that on MacOS we need to
    # use the --user flag as otherwise pip will complain about permissions.
    pip3 install --upgrade pip --user
    pip3 install --upgrade setuptools --user
    pip3 install . --user
  )
}

run_bazel_tests() {
  (
    cd python
    use_bazel.sh $(cat .bazelversion)

    time bazel build -- ...
    time bazel test -- ...
  )
}

install_pip_package
run_bazel_tests
