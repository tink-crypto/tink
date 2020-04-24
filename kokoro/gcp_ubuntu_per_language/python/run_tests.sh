#!/bin/bash

set -euo pipefail
cd ${KOKORO_ARTIFACTS_DIR}/git/tink

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


install_pip_package() {
  # Check if we can build Tink python package.
  (
    cd python
    # Needed for setuptools

    use_bazel.sh $(cat .bazelversion)
    # Install the proto compiler
    PROTOC_ZIP='protoc-3.11.4-linux-x86_64.zip'
    curl -OL "https://github.com/protocolbuffers/protobuf/releases/download/v3.11.4/${PROTOC_ZIP}"
    sudo unzip -o "${PROTOC_ZIP}" -d /usr/local bin/protoc
    # Update pip and start setup
    pip3 install --upgrade pip
    pip3 install --upgrade setuptools
    pip3 install .
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

install_python3
install_pip_package
run_bazel_tests
