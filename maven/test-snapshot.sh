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

test_java_snapshot() {
  local test_tmpdir="/tmp/tink_maven_snapshot_test"
  mkdir -p $test_tmpdir

  local test_util="tools/testing/cross_language/test_util.sh"
  source $test_util || exit 1

  local pom_file="examples/helloworld/java/pom.xml"
  mvn package -f $pom_file

  local plaintext="$test_tmpdir/plaintext.bin"
  local encrypted="$test_tmpdir/encrypted.bin"
  local decrypted="$test_tmpdir/decrypted.bin"
  local keyset="$test_tmpdir/keyset.cfg"

  openssl rand 128 -out $plaintext
  mvn exec:java -f $pom_file \
    -Dexec.args="encrypt --keyset ${keyset} --in ${plaintext} --out ${encrypted}"
  mvn exec:java -f $pom_file \
    -Dexec.args="decrypt --keyset ${keyset} --in ${encrypted} --out ${decrypted}"

  assert_files_equal $plaintext $decrypted

  rm -rf $test_tmpdir
}

test_android_snapshot() {
  ./examples/helloworld/android/gradlew -p ./examples/helloworld/android build
}

echo -e "Testing new Maven snapshot"

test_java_snapshot

test_android_snapshot

echo -e "New Maven snapshot works"
