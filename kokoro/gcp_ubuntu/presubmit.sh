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

# Build
cd github/tink/

# bazel sandbox doesn't work with Kokoro's MacOS image, see b/38040081.
bazel build --strategy=CppCompile=standalone --strategy=Turbine=standalone \
  --strategy=ProtoCompile=standalone --strategy=GenProto=standalone \
  --strategy=GenRule=standalone --strategy=GenProtoDescriptorSet=standalone \
  --sandbox_tmpfs_path=$TMP -- //... -//objc/...

# Run all tests.
bazel test --strategy=TestRunner=standalone --test_output=all -- //... -//objc/...
