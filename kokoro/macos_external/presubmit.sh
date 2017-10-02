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

# Default values for iOS SDK and Xcode. Can be overriden by another script.
: "${IOS_SDK_VERSION:=10.2}"
: "${XCODE_VERSION:=8.2.1}"

BAZEL_BIN="${KOKORO_GFILE_DIR}/bazel-c6122b6ad35ebbed61036b0a2bcfea92b10adb8f-darwin-x86_64"

DISABLE_SANDBOX="--strategy=GenRule=standalone --strategy=Turbine=standalone \
--strategy=CppCompile=standalone --strategy=ProtoCompile=standalone \
--strategy=GenProto=standalone --strategy=GenProtoDescriptorSet=standalone \
--strategy=ObjcCompile=standalone"

export DEVELOPER_DIR="/Applications/Xcode_${XCODE_VERSION}.app/Contents/Developer"

pushd "$TMP"
mkdir jdk; cd jdk;
cp "${KOKORO_GFILE_DIR}/jdk-8u131-macosx-x64.tgz" ./
tar xf jdk-8u131-macosx-x64.tgz

export ANDROID_HOME="/Users/kbuilder/Library/Android/sdk"
export JAVA_HOME="${PWD}/Home"
export PATH="${JAVA_HOME}/bin:$PATH"
chmod -R a+rx "${JAVA_HOME}"
popd

# fixing https://stackoverflow.com/questions/36908041/git-could-not-expand-include-path-gitcinclude-fatal-bad-config-file-line
sudo sed -i.bak s#~#/Users/kbuilder#g /usr/local/git/etc/gitconfig

chmod +x "${BAZEL_BIN}"

echo "using bazel binary: ${BAZEL_BIN}"
${BAZEL_BIN} version

echo "using java binary: " `which java`
java -version

cd github/tink/

time bazel fetch ...

# Build all the iOS targets.
time ${BAZEL_BIN} build \
  $DISABLE_SANDBOX \
  --compilation_mode=dbg \
  --dynamic_mode=off \
  --cpu=ios_x86_64 \
  --ios_cpu=x86_64 \
  --sandbox_tmpfs_path=$TMP \
  --experimental_enable_objc_cc_deps \
  --ios_sdk_version="${IOS_SDK_VERSION}" \
  --xcode_version="${XCODE_VERSION}" \
  --verbose_failures \
  //objc/... || \
  ( ls -l ; df -h / ; exit 1 )

echo "bazel obj-c passed"

# Test all targets except iOS.
# bazel sandbox doesn't work with Kokoro's MacOS image, see b/38040081.
time ${BAZEL_BIN} test --sandbox_tmpfs_path=$TMP $DISABLE_SANDBOX -- //... \
-//objc/... || ( ls -l ; df -h / ; exit 1 )

echo "bazel non objc-c passed"
