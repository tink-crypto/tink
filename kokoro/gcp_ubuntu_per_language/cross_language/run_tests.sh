#!/bin/bash

set -euo pipefail

CURRENT_BAZEL_VERSION=""

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

use_bazel() {
  local candidate_version="$1"
  if [[ "${candidate_version}" != "${CURRENT_BAZEL_VERSION}" ]]; then
    CURRENT_BAZEL_VERSION="${candidate_version}"
    if [[ -n "${KOKORO_ROOT:-}" ]] ; then
      use_bazel.sh "${candidate_version}"
    else
      bazel --version
    fi
  fi
}

main() {
  if [[ -n "${KOKORO_ROOT:-}" ]] ; then
    install_python3
    cd "${KOKORO_ARTIFACTS_DIR}/git/tink"
  fi
  (
    cd testing/cc
    use_bazel "$(cat .bazelversion)"
    time bazel build -- ...
    time bazel test --test_output=errors -- ...
  )
  (
    cd testing/go
    use_bazel "$(cat .bazelversion)"
    time bazel build -- ...
    time bazel test --test_output=errors -- ...
  )
  (
    cd testing/java_src
    use_bazel "$(cat .bazelversion)"
    time bazel build -- ...
    time bazel build :testing_server_deploy.jar
    time bazel test --test_output=errors -- ...
  )
  (
    cd testing/python
    use_bazel "$(cat .bazelversion)"
    time bazel build -- ...
    time bazel test --test_output=errors -- ...
  )

  local testing_dir="${PWD}/testing"
  (
    cd testing/cross_language
    use_bazel "$(cat .bazelversion)"
    time bazel test \
      --test_env testing_dir="${testing_dir}" --test_output=errors -- ...
  )
}

main "$@"
