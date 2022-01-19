#!/bin/bash

# Copyright 2021 Google LLC
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

set -x

if [[ -z "${KOKORO_ROOT}" ]] ; then
  exit 0
fi

readonly PLATFORM="$(uname | tr '[:upper:]' '[:lower:]')"

if [[ "${PLATFORM}" == 'darwin' ]]; then
  export JAVA_OPTS="-Djava.net.preferIPv6Addresses=true"
fi

# Install build-tools.
(yes || true) | "${ANDROID_HOME}/tools/bin/sdkmanager" "build-tools;30.0.3"

# Install all necessary parts of the Android SDK.
(yes || true) | "${ANDROID_HOME}/tools/bin/sdkmanager" "platform-tools" \
  "platforms;android-29" "platforms;android-30" "platforms;android-31"
