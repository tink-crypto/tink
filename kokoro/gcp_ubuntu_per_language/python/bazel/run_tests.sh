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

run_bazel_tests() {
  (
    cd python
    use_bazel.sh $(cat .bazelversion)

    time bazel build -- ...
    time bazel test --test_output=errors -- ...
  )
}

install_python3
run_bazel_tests
