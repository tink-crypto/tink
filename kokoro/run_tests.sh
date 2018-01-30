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

# Workaround for some unknown issue in Kokoro.
rm -f ~/.bazelrc

PLATFORM=`uname | tr '[:upper:]' '[:lower:]'`

# Using Bazel 0.9.0.
BAZEL_BIN="${KOKORO_GFILE_DIR}/bazel-${PLATFORM}-x86_64"

DISABLE_SANDBOX="--strategy=GenRule=standalone --strategy=Turbine=standalone \
--strategy=CppCompile=standalone --strategy=ProtoCompile=standalone \
--strategy=GenProto=standalone --strategy=GenProtoDescriptorSet=standalone \
--sandbox_tmpfs_path=${TMP}"

chmod +x "${BAZEL_BIN}"

echo "using bazel binary: ${BAZEL_BIN}"
${BAZEL_BIN} version

echo "using java binary: " `which java`
java -version

echo "using go: " `which go`
go version

run_linux_tests() {
  time ${BAZEL_BIN} fetch ...

  # Build all targets, except objc.
  time ${BAZEL_BIN} build $DISABLE_SANDBOX \
  -- //... \
  -//objc/... || ( ls -l ; df -h / ; exit 1 )

  # Run all tests, except manual and objc tests.
  time ${BAZEL_BIN} test --strategy=TestRunner=standalone --test_output=all \
  -- //... \
  -//objc/... || ( ls -l ; df -h / ; exit 1 )
}

run_macos_tests() {
  # Default values for iOS SDK and Xcode. Can be overriden by another script.
  : "${IOS_SDK_VERSION:=10.2}"
  : "${XCODE_VERSION:=8.2.1}"

  time ${BAZEL_BIN} fetch ...

  # Build all the iOS targets.
  time ${BAZEL_BIN} build $DISABLE_SANDBOX \
  --compilation_mode=dbg \
  --dynamic_mode=off \
  --cpu=ios_x86_64 \
  --ios_cpu=x86_64 \
  --experimental_enable_objc_cc_deps \
  --ios_sdk_version="${IOS_SDK_VERSION}" \
  --xcode_version="${XCODE_VERSION}" \
  --verbose_failures \
  //objc/... || ( ls -l ; df -h / ; exit 1 )
}

if [[ $PLATFORM == 'darwin' ]]; then
  export DEVELOPER_DIR="/Applications/Xcode_${XCODE_VERSION}.app/Contents/Developer"
  export ANDROID_HOME="/Users/kbuilder/Library/Android/sdk"
  run_macos_tests
fi

run_linux_tests
