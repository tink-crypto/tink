#!/bin/bash
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


VERSION_FILE="$TEST_SRCDIR/tink_base/tink_version.bzl"
ROOT_DIR="$TEST_SRCDIR/tools"
CC_VERSION_CLI="$ROOT_DIR/testing/cc/version_cli_cc"
JAVA_VERSION_CLI="$ROOT_DIR/testing/version_cli_java"
TEST_UTIL="$ROOT_DIR/testing/cross_language/test_util.sh"

source $TEST_UTIL || exit 1

#############################################################################
##### Run the actual tests.
TINK_VERSION=$(grep "TINK_VERSION_LABEL" $VERSION_FILE | cut -d \" -f 2)
echo "CONFIG: $TINK_VERSION"
CC_TINK_VERSION=$($CC_VERSION_CLI)
echo "CC: $CC_TINK_VERSION"
JAVA_TINK_VERSION=$($JAVA_VERSION_CLI)
echo "JAVA: $JAVA_TINK_VERSION"
assert_equals "$TINK_VERSION" "$CC_TINK_VERSION"
assert_equals "$TINK_VERSION" "$JAVA_TINK_VERSION"
