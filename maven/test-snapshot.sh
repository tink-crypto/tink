#!/bin/bash

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

# Fail on any error.
set -e

# Display commands to stderr.
set -x

# Version of Android build-tools required for gradle.
readonly ANDROID_BUILD_TOOLS_VERSION="28.0.3"

test_java_snapshot() {
  local -r test_tmpdir="$(mktemp -d)"
  mkdir -p "${test_tmpdir}"

  local -r test_util="tools/testing/cross_language/test_util.sh"
  source "${test_util}" || exit 1

  local -r pom_file="examples/java_src/helloworld/pom.xml"

  mvn package -f "${pom_file}"

  local -r plaintext="${test_tmpdir}/plaintext.bin"
  local -r encrypted="${test_tmpdir}/encrypted.bin"
  local -r decrypted="${test_tmpdir}/decrypted.bin"
  local -r keyset="${test_tmpdir}/keyset.cfg"

  openssl rand 128 > "${plaintext}"
  mvn exec:java -f "${pom_file}" \
    -Dexec.args="encrypt --keyset ${keyset} --in ${plaintext} --out ${encrypted}"
  mvn exec:java -f $pom_file \
    -Dexec.args="decrypt --keyset ${keyset} --in ${encrypted} --out ${decrypted}"

  assert_files_equal "${plaintext}" "${decrypted}"

  rm -rf "${test_tmpdir}"
}

test_android_snapshot() {
  # Only in the Kokoro environment.
  if [[ -n "${KOKORO_ROOT}" ]]; then
    yes | "${ANDROID_HOME}/tools/bin/sdkmanager" \
      "build-tools;${ANDROID_BUILD_TOOLS_VERSION}"
    yes | "${ANDROID_HOME}/tools/bin/sdkmanager" --licenses
  fi

  ./examples/android/helloworld/gradlew -p ./examples/android/helloworld build
}

main() {
  echo -e "Testing new Maven snapshot"
  test_java_snapshot
  test_android_snapshot
  echo -e "New Maven snapshot works"
}

main "$@"
