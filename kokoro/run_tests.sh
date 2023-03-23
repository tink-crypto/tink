# Copyright 2017 Google Inc.
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
####################################################################################

#!/bin/bash

# Fail on any error.
set -e

# Display commands to stderr.
set -x

readonly PLATFORM="$(uname | tr '[:upper:]' '[:lower:]')"

IS_KOKORO="false"
if [[ -n "${KOKORO_ROOT}" ]]; then
  IS_KOKORO="true"
fi
readonly IS_KOKORO

use_bazel() {
  local -r bazel_version="$1"
  if [[ "${IS_KOKORO}" == "false" ]]; then
    # Do nothing.
    return 0
  fi
  if ! command -v "bazelisk" &> /dev/null; then
    use_bazel.sh "${bazel_version}"
  fi
}

run_cc_tests() {
  use_bazel "$(cat cc/.bazelversion)"
  ./kokoro/testutils/run_bazel_tests.sh "cc"
}

run_go_tests() {
  use_bazel "$(cat go/.bazelversion)"
  ./kokoro/testutils/run_bazel_tests.sh "go"
}

run_py_tests() {
  use_bazel "$(cat python/.bazelversion)"
  ./kokoro/testutils/run_bazel_tests.sh "python"
}

run_tools_tests() {
  use_bazel "$(cat tools/.bazelversion)"
  local -a MANUAL_TOOLS_TARGETS
  if [[ "${IS_KOKORO}" == "true" ]]; then
    MANUAL_TOOLS_TARGETS+=(
      "//testing/cc:aws_kms_aead_test"
      "//testing/cc:gcp_kms_aead_test"
      "//tinkey/src/test/java/com/google/crypto/tink/tinkey:AddKeyCommandTest"
      "//tinkey/src/test/java/com/google/crypto/tink/tinkey:CreateKeysetCommandTest"
      "//tinkey/src/test/java/com/google/crypto/tink/tinkey:CreatePublicKeysetCommandTest"
      "//tinkey/src/test/java/com/google/crypto/tink/tinkey:RotateKeysetCommandTest"
    )
  fi
  readonly MANUAL_TOOLS_TARGETS
  ./kokoro/testutils/run_bazel_tests.sh "tools" "${MANUAL_TOOLS_TARGETS[@]}"
}

run_java_tests() {
  use_bazel "$(cat java_src/.bazelversion)"
  local -a MANUAL_JAVA_TARGETS
  if [[ "${IS_KOKORO}" == "true" ]]; then
    MANUAL_JAVA_TARGETS+=(
      "//src/test/java/com/google/crypto/tink/integration/gcpkms:GcpKmsIntegrationTest"
    )
  fi
  readonly MANUAL_JAVA_TARGETS
  ./kokoro/testutils/run_bazel_tests.sh "java_src" "${MANUAL_JAVA_TARGETS[@]}"
}

run_java_apps_tests() {
  use_bazel "$(cat apps/.bazelversion)"
  ./kokoro/testutils/run_bazel_tests.sh "apps"
}

run_javascript_tests() {
  use_bazel "$(cat javascript/.bazelversion)"
  # On MacOS, Javascript compilation fails with
  # clang: error: unknown argument: '-fno-canonical-system-headers'
  # The internet recommends to run "bazel clean --expunge"
  if [[ "${PLATFORM}" == 'darwin' ]]; then
    (
      cd javascript
      bazelisk clean --expunge
    )
  fi
  ./kokoro/testutils/run_bazel_tests.sh "javascript"
}

run_cc_examples_tests() {
  use_bazel "$(cat cc/examples/.bazelversion)"
  ./kokoro/testutils/run_bazel_tests.sh "cc/examples"
}

run_java_examples_tests() {
  use_bazel "$(cat java_src/examples/.bazelversion)"
  local -a MANUAL_EXAMPLE_JAVA_TARGETS
  if [[ "${IS_KOKORO}" == "true" ]]; then
    MANUAL_EXAMPLE_JAVA_TARGETS=(
      "//gcs:gcs_envelope_aead_example_test"
      "//encryptedkeyset:encrypted_keyset_example_test"
      "//envelopeaead:envelope_aead_example_test"
    )
  fi
  readonly MANUAL_EXAMPLE_JAVA_TARGETS
  ./kokoro/testutils/run_bazel_tests.sh "java_src/examples" \
    "${MANUAL_EXAMPLE_JAVA_TARGETS[@]}"
}

run_py_examples_tests() {
  use_bazel "$(cat python/examples/.bazelversion)"
  ## Install Tink and its dependencies via pip for the examples/python tests.
  source ./kokoro/testutils/install_tink_via_pip.sh "${PWD}/python"
  if [[ "${IS_KOKORO}" == "true" ]]; then
    # Install dependencies for the examples/python tests.
    pip3 install "${PIP_FLAGS[@]}" \
      -r python/examples/requirements.txt \
      -c python/examples/constraints.in
  fi

  local -a MANUAL_EXAMPLE_PYTHON_TARGETS
  if [[ "${IS_KOKORO}" == "true" ]]; then
    MANUAL_EXAMPLE_PYTHON_TARGETS=(
      "//gcs:gcs_envelope_aead_test_package"
      "//gcs:gcs_envelope_aead_test"
      "//envelope_aead:envelope_test_package"
      "//envelope_aead:envelope_test"
      "//encrypted_keyset:encrypted_keyset_test_package"
      "//encrypted_keyset:encrypted_keyset_test"
    )
  fi
  readonly MANUAL_EXAMPLE_PYTHON_TARGETS
  ./kokoro/testutils/run_bazel_tests.sh "python/examples" \
    "${MANUAL_EXAMPLE_PYTHON_TARGETS[@]}"
}

run_all_tests() {
  # Only run these tests if exeucting a Kokoro GitHub continuous integration
  # job or if running locally (e.g. as part of release.sh).
  #
  # TODO(b/228529710): Use an easier to maintain approach to test parity.
  if [[ "${KOKORO_JOB_NAME:-}" =~ ^tink/github \
        || -z "${KOKORO_JOB_NAME+x}" ]]; then
    run_cc_tests
    run_java_tests
    run_go_tests
    run_py_tests
    run_tools_tests
    run_java_apps_tests
  fi
  run_javascript_tests
  run_cc_examples_tests
  run_java_examples_tests
  run_py_examples_tests
}

main() {
  # Initialization for Kokoro environments.
  if [[ "${IS_KOKORO}" == "true" ]]; then
    cd "${KOKORO_ARTIFACTS_DIR}"/git*/tink*
    # Install protoc.
    source ./kokoro/testutils/install_protoc.sh

    if [[ "${PLATFORM}" == 'linux' ]]; then
      # Sourcing required to update callers environment.
      source ./kokoro/testutils/install_python3.sh
      ./kokoro/testutils/upgrade_gcc.sh
    fi

    if [[ "${PLATFORM}" == 'darwin' ]]; then
      # Default values for iOS SDK and Xcode. Can be overriden by another script.
      : "${IOS_SDK_VERSION:=13.2}"
      : "${XCODE_VERSION:=11.3}"

      export DEVELOPER_DIR="/Applications/Xcode_${XCODE_VERSION}.app/Contents/Developer"
      export JAVA_HOME=$(/usr/libexec/java_home -v "1.8.0_292")
      export ANDROID_HOME="/usr/local/share/android-sdk"
      export COURSIER_OPTS="-Djava.net.preferIPv6Addresses=true"

      # TODO(b/155225382): Avoid modifying the sytem Python installation.
      pip3 install --user protobuf
    fi

    ./kokoro/testutils/copy_credentials.sh "go/testdata" "all"
    ./kokoro/testutils/copy_credentials.sh "java_src/examples/testdata" "gcp"
    ./kokoro/testutils/copy_credentials.sh "java_src/testdata" "all"
    ./kokoro/testutils/copy_credentials.sh "python/examples/testdata" "gcp"
    ./kokoro/testutils/copy_credentials.sh "python/testdata" "all"
    ./kokoro/testutils/copy_credentials.sh "tools/testdata" "all"

    ./kokoro/testutils/update_android_sdk.sh
    # Sourcing required to update callers environment.
    source ./kokoro/testutils/install_go.sh
  fi

  # Verify required environment variables.

  # Required for building Java binaries.
  if [[ -z "${ANDROID_HOME}" ]]; then
    echo "The ANDROID_HOME environment variable must be set."
    exit 4
  fi

  if [[ -z "${TMP}" ]]; then
    echo "The TMP environment variable must be set."
    exit 4
  fi

  echo "using java binary: $(which java)"
  java -version

  echo "Using go binary from $(which go): $(go version)"

  echo "using python: $(which python)"
  python --version

  echo "using python3: $(which python3)"
  python3 --version

  echo "using pip3: $(which pip3)"
  pip3 --version
  pip3 list

  echo "using protoc: $(which protoc)"
  protoc --version

  run_all_tests
}

main "$@"
