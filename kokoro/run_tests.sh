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

# TODO(b/140615798): Remove once fixed.
DISABLE_GRPC_ON_MAC_OS=""
if [[ "${PLATFORM}" == 'darwin' ]]; then
  DISABLE_GRPC_ON_MAC_OS="-//integration/gcpkms/..."
fi
readonly DISABLE_GRPC_ON_MAC_OS

fail_with_debug_output() {
  ls -l
  df -h /
  exit 1
}

run_linux_tests() {
  local workspace_dir="$1"

  local -a TEST_FLAGS=( --strategy=TestRunner=standalone --test_output=all )
  readonly TEST_FLAGS
  (
    cd ${workspace_dir}
    time bazel build -- ... || fail_with_debug_output
    time bazel test "${TEST_FLAGS[@]}" -- ... || fail_with_debug_output
  )
}

run_all_linux_tests() {
  # TODO(b/140615798): Remove the customized test once the issue is fixed.
  #run_linux_tests "cc"
  local -a TEST_FLAGS=( --strategy=TestRunner=standalone --test_output=all )
  readonly TEST_FLAGS
  (
    cd cc
    time bazel build -- ... || fail_with_debug_output
    time bazel test "${TEST_FLAGS[@]}" -- ... ${DISABLE_GRPC_ON_MAC_OS} \
        || fail_with_debug_output
  )
  run_linux_tests "java"
  run_linux_tests "go"
  run_linux_tests "python"
  run_linux_tests "examples/cc"
  #run_linux_tests "examples/java_src"
  run_linux_tests "tools"
  run_linux_tests "apps"
}

run_macos_tests() {
  # Default values for iOS SDK and Xcode. Can be overriden by another script.
  : "${IOS_SDK_VERSION:=13.2}"
  : "${XCODE_VERSION:=11.3}"

  local -a BAZEL_FLAGS=(
    --compilation_mode=dbg --dynamic_mode=off --cpu=ios_x86_64
    --ios_cpu=x86_64 --experimental_enable_objc_cc_deps
    --ios_sdk_version="${IOS_SDK_VERSION}"
    --xcode_version="${XCODE_VERSION}" --verbose_failures
    --test_output=all
  )
  readonly BAZEL_FLAGS

  (
    cd objc

    # Build the iOS targets.
    time bazel build "${BAZEL_FLAGS[@]}" ... || fail_with_debug_output

    # Run the iOS tests.
    time bazel test "${BAZEL_FLAGS[@]}" :TinkTests || fail_with_debug_output
  )
}

main() {
  # Only in Kokoro environments.
  if [[ -n "${KOKORO_ROOT}" ]]; then
    # TODO(b/73748835): Workaround on Kokoro.
    rm -f ~/.bazelrc

    # TODO(b/131821833) Use the latest version of Bazel.
    use_bazel.sh $(cat .bazelversion)

    if [[ "${PLATFORM}" == 'darwin' ]]; then
      export DEVELOPER_DIR="/Applications/Xcode_${XCODE_VERSION}.app/Contents/Developer"
      export ANDROID_HOME="/Users/kbuilder/Library/Android/sdk"
    fi
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

  echo "using bazel binary: $(which bazel)"
  bazel version

  echo "using java binary: $(which java)"
  java -version

  echo "using go: $(which go)"
  go version

  run_all_linux_tests

  if [[ "${PLATFORM}" == 'darwin' ]]; then
    # TODO(przydatek): re-enable after ObjC WORKSPACE is added.
    # run_macos_tests
    echo "*** ObjC tests not enabled yet."
  fi
}

main "$@"
