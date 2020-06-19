#!/bin/bash

set -euo pipefail

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

install_python3

cd ${KOKORO_ARTIFACTS_DIR}/git/tink/testing
use_bazel.sh $(cat .bazelversion)

cd ${KOKORO_ARTIFACTS_DIR}/git/tink/testing/cc
time bazel build -- ...
time bazel test --test_output=errors -- ...

cd ${KOKORO_ARTIFACTS_DIR}/git/tink/testing/go
time bazel build -- ...
time bazel test --test_output=errors -- ...

cd ${KOKORO_ARTIFACTS_DIR}/git/tink/testing/java_src
time bazel build -- ...
time bazel build :testing_server_deploy.jar
time bazel test --test_output=errors -- ...

cd ${KOKORO_ARTIFACTS_DIR}/git/tink/testing/python
time bazel build -- ...
time bazel test --test_output=errors -- ...

cd ${KOKORO_ARTIFACTS_DIR}/git/tink/testing/cross_language
time bazel test --test_env testing_dir=${KOKORO_ARTIFACTS_DIR}/git/tink/testing --test_output=errors -- ...
