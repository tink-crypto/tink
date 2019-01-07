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

PLATFORM=`uname | tr '[:upper:]' '[:lower:]'`

declare -a DISABLE_SANDBOX_ARGS
DISABLE_SANDBOX_ARGS=(
  --strategy=GenRule=standalone
  --strategy=Turbine=standalone
  --strategy=CppCompile=standalone
  --strategy=ProtoCompile=standalone
  --strategy=GenProto=standalone
  --strategy=GenProtoDescriptorSet=standalone
  --sandbox_tmpfs_path=${TMP}
)
readonly DISABLE_SANDBOX_ARGS

# Workaround b/73748835#comment5 on Kokoro.
if ! [ -z "${KOKORO_ROOT}" ]; then
  rm -f ~/.bazelrc
  # Install the latest version of Bazel.
  use_bazel.sh latest
  if [[ "$PLATFORM" == 'darwin' ]]; then
    export DEVELOPER_DIR="/Applications/Xcode_${XCODE_VERSION}.app/Contents/Developer"
    export ANDROID_HOME="/Users/kbuilder/Library/Android/sdk"
  fi
fi

echo "using bazel binary: $(which bazel)"
bazel version

echo "using java binary: $(which java)"
java -version

echo "using go: $(which go)"
go version

run_linux_tests() {
  time bazel fetch ...

  # Build all targets, except objc.
  time bazel build "${DISABLE_SANDBOX_ARGS[@]}" \
  -- //... \
  -//objc/... || ( ls -l ; df -h / ; exit 1 )

  # Run all tests, except manual and objc tests.
  time bazel test \
  --strategy=TestRunner=standalone --test_output=all \
  -- //... \
  -//objc/... || ( ls -l ; df -h / ; exit 1 )
}

run_macos_tests() {
  # Default values for iOS SDK and Xcode. Can be overriden by another script.
  : "${IOS_SDK_VERSION:=11.2}"
  : "${XCODE_VERSION:=9.2}"

  time bazel fetch ...

  # Build all the iOS targets.
  time bazel build "${DISABLE_SANDBOX_ARGS[@]}" \
  --compilation_mode=dbg \
  --dynamic_mode=off \
  --cpu=ios_x86_64 \
  --ios_cpu=x86_64 \
  --experimental_enable_objc_cc_deps \
  --ios_sdk_version="${IOS_SDK_VERSION}" \
  --xcode_version="${XCODE_VERSION}" \
  --verbose_failures \
  --test_output=all \
  //objc/... || ( ls -l ; df -h / ; exit 1 )

  # Run the iOS tests.
  time bazel test "${DISABLE_SANDBOX_ARGS[@]}" \
  --compilation_mode=dbg \
  --dynamic_mode=off \
  --cpu=ios_x86_64 \
  --ios_cpu=x86_64 \
  --experimental_enable_objc_cc_deps \
  --ios_sdk_version="${IOS_SDK_VERSION}" \
  --xcode_version="${XCODE_VERSION}" \
  --verbose_failures \
  --test_output=all \
  //objc:TinkTests || ( ls -l ; df -h / ; exit 1 )
}

run_linux_tests

if [[ "${PLATFORM}" == 'darwin' ]]; then
  run_macos_tests
fi

