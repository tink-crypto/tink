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

# TODO(b/140615798)
DISABLE_GRPC_ON_MAC_OS=""
DISABLE_NONBAZEL_ON_MAC_OS=""
if [[ "${PLATFORM}" == 'darwin' ]]; then
  DISABLE_GRPC_ON_MAC_OS="-//integration/gcpkms/..."
  DISABLE_NON_BAZEL_ON_MAC_OS="-//helloworld/cc:non_bazel_build_test"
fi

echo "using bazel binary: $(which bazel)"
bazel version

echo "using java binary: $(which java)"
java -version

echo "using go: $(which go)"
go version

# TODO(b/141297103): add Python build and tests.
run_linux_tests() {
  # ------------------- C++
  cd cc/
  time bazel build -- ... || ( ls -l ; df -h / ; exit 1 )
  time bazel test \
      --strategy=TestRunner=standalone --test_output=all \
      -- ... \
      ${DISABLE_GRPC_ON_MAC_OS} \
      || ( ls -l ; df -h / ; exit 1 )

  # ------------------- Java
  cd ../java
  time bazel build -- ... || ( ls -l ; df -h / ; exit 1 )
  time bazel test \
      --strategy=TestRunner=standalone --test_output=all \
      -- ... || ( ls -l ; df -h / ; exit 1 )

  # ------------------- Go
  cd ../go
  time bazel build -- ... || ( ls -l ; df -h / ; exit 1 )
  time bazel test \
      --strategy=TestRunner=standalone --test_output=all \
      -- ... || ( ls -l ; df -h / ; exit 1 )

  # ------------------- examples
  cd ../examples
  time bazel build -- ... || ( ls -l ; df -h / ; exit 1 )
  time bazel test \
      --strategy=TestRunner=standalone --test_output=all \
      -- ... \
      ${DISABLE_NON_BAZEL_ON_MAC_OS} \
      || ( ls -l ; df -h / ; exit 1 )

  # ------------------- tools and cross-language tests
  cd ../tools
  time bazel build -- ... || ( ls -l ; df -h / ; exit 1 )
  time bazel test \
      --strategy=TestRunner=standalone --test_output=all \
      -- ... || ( ls -l ; df -h / ; exit 1 )

  # --- return to the root directory
  cd ..
}

run_macos_tests() {
  # Default values for iOS SDK and Xcode. Can be overriden by another script.
  : "${IOS_SDK_VERSION:=13.0}"
  : "${XCODE_VERSION:=11.0}"

  # --- Build all the iOS targets.
  cd objc
  time bazel build \
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

  # --- Run the iOS tests.
  time bazel test \
  --compilation_mode=dbg \
  --dynamic_mode=off \
  --cpu=ios_x86_64 \
  --ios_cpu=x86_64 \
  --experimental_enable_objc_cc_deps \
  --ios_sdk_version="${IOS_SDK_VERSION}" \
  --xcode_version="${XCODE_VERSION}" \
  --verbose_failures \
  --test_output=all \
  :TinkTests || ( ls -l ; df -h / ; exit 1 )

  # --- return to the root directory
  cd ..
}

run_linux_tests

if [[ "${PLATFORM}" == 'darwin' ]]; then
  # TODO(przydatek): re-enable after ObjC WORKSPACE is added.
  # run_macos_tests
  echo "*** ObjC tests not enabled yet."
fi
