#!/bin/bash
# Copyright 2020 Google LLC
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
################################################################################

set -euo pipefail

export XCODE_VERSION="14.1"
export DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
export ANDROID_HOME="/usr/local/share/android-sdk"
export COURSIER_OPTS="-Djava.net.preferIPv6Addresses=true"

if [[ -n "${KOKORO_ROOT:-}" ]] ; then
  cd "$(echo "${KOKORO_ARTIFACTS_DIR}"/git*/tink)"
  export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-8-latest/Contents/Home
fi

./kokoro/testutils/update_android_sdk.sh
./kokoro/testutils/run_bazel_tests.sh java_src
