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

    # Set path to Tink base folder
    export TINK_PYTHON_SETUPTOOLS_OVERRIDE_BASE_PATH=$PWD/..

    # Update pip and install all requirements. Note that on MacOS we need to
    # use the --user flag as otherwise pip will complain about permissions.
    pip3 install --upgrade pip --user
    pip3 install --upgrade setuptools --user
    pip3 install . --user
  )
}

run_tests_with_package() {
  # Get root certificates for gRPC
  wget https://raw.githubusercontent.com/grpc/grpc/master/etc/roots.pem
  export GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=${PWD}/roots.pem

  # Set path to Tink base folder
  export TINK_SRC_PATH=${PWD}

  # Run Python tests directly so the package is used.
  # We exclude tests in tink/cc/pybind: they are implementation details and may
  # depend on a testonly shared object.
  find python/tink/ -not -path "*cc/pybind*" -type f -name "*_test.py" -print0 | xargs -0 -n1 python3
}

install_pip_package
run_tests_with_package
