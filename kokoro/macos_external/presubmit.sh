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

DISABLE_SANDBOX="--strategy=CppCompile=standalone \
--strategy=Turbine=standalone --strategy=ProtoCompile=standalone \
--strategy=GenProto=standalone --strategy=GenProtoDescriptorSet=standalone \
--strategy=ObjcCompile=standalone"

cd github/tink/

# build the iOS targets
bazel build \
  $DISABLE_SANDBOX \
  --compilation_mode=dbg \
  --dynamic_mode=off \
  --cpu=ios_armv7 \
  --ios_multi_cpus=armv7,arm64 \
  --watchos_cpus=armv7k \
  --experimental_enable_objc_cc_deps \
  --ios_sdk_version="${IOS_SDK_VERSION}" \
  --xcode_version="${XCODE_VERSION}" \
  --verbose_failures \
  //objc/... || \
  ( ls -l ; df -h / ; exit 1 )

echo "bazel obj-c passed"

# bazel sandbox doesn't work with Kokoro's MacOS image, see b/38040081.
bazel build $DISABLE_SANDBOX -- //... -//objc/... || ( ls -l ; df -h / ; exit 1 )

echo "bazel c++ / java passed"

# Run all tests.
bazel test --strategy=TestRunner=standalone --test_output=all -- //... -//objc/...
