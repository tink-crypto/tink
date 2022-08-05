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


#######################################
# Checks if the maven targets in BUILD.bazel have all the required dependencies.
#  * ":tink" should have all java_libraries except integration as dependencies.
#  * ":tink-android" should have all android_libraries except integration as
#    dependencies.
#  * ":tink-awskms should have all java_libraries in the awskms folder as
#    dependencies.
#  * ":tink-gcpkms should have all java_libraries in the gcpkms folder as
#    dependencies.
#
# Globals:
#   None (except cwd)
# Arguments:
# Outputs:
#   Writes to stdout
#######################################
test_build_bazel_file() {
  pushd java_src
  local main_dir="//src/main/java/com/google/crypto/tink"
  # src_android contains android_library targets where the source file differes for java and android.
  local android_dir="//src_android/main/java/com/google/crypto/tink"
  local integration_dir="${main_dir}/integration"

  # Targets in //src/main/java/com/google/crypto/tink of type "java_library",
  # excluding:
  #   * testonly targets
  #   * targets in //src/main/java/com/google/crypto/tink/integration
  local all_java_libs="$(mktemp)"
  bazel query "kind(java_library,${main_dir}/...) except attr(testonly,1,${main_dir}/...) except kind(java_library,${integration_dir}/...)" > "${all_java_libs}"

  # Targets in //src/main/java/com/google/crypto/tink of type "android_library"
  # excluding testonly targets
  local all_android_libs="$(mktemp)"
  bazel query "kind(android_library,${main_dir}/...) except attr(testonly,1,${main_dir}/...)" > "${all_android_libs}"

  # Targets in //src_android/main/java/com/google/crypto/tink of type "android_library",
  # excluding:
  #   * testonly targets
  bazel query "kind(android_library,${android_dir}/...) except attr(testonly,1,${main_dir}/...)" >> "${all_android_libs}"


  # Targets in //src/main/java/com/google/crypto/tink/integration/awskms of
  # type "java_library"
  local all_aws_kms_libs="$(mktemp)"
  bazel query "kind(java_library,${integration_dir}/awskms/...)" > "${all_aws_kms_libs}"

  # Targets in //src/main/java/com/google/crypto/tink/integration/gcpkms of
  # type "java_library"
  all_gcp_kms_libs="$(mktemp)"
  bazel query "kind(java_library,${integration_dir}/gcpkms/...)" > "${all_gcp_kms_libs}"
  popd

  python3 kokoro/testutils/create_main_build_file.py \
    "${all_java_libs}" \
    "${all_android_libs}" \
    "${all_aws_kms_libs}" \
    "${all_gcp_kms_libs}" > java_src/BUILD.bazel.generated

  buildifier java_src/BUILD.bazel.generated

  if ! cmp -s java_src/BUILD.bazel java_src/BUILD.bazel.generated ; then
    echo "Files BUILD.bazel and BUILD.bazel.generated are different."
    echo "#=============== BROKEN file //third_party/tink/java_src/BUILD.bazel. Should be: "
    cat java_src/BUILD.bazel.generated
    echo "#=============== END BROKEN file //third_party/tink/java_src/BUILD.bazel."
    echo "#=============== To fix this, run (from <Your CitC Client>/google3): "
    echo "g4 open third_party/tink/java_src/BUILD.bazel"
    echo "patch third_party/tink/java_src/BUILD.bazel<<END_OF_PATCH"
    ## We run under "set -e", so exit on error. Diff returns a non-zero exit
    ## status we flip it here.
    ! diff java_src/BUILD.bazel java_src/BUILD.bazel.generated
    echo "END_OF_PATCH"
    echo "#=============== End of command"
    exit 1
  fi
}

if [[ -n "${KOKORO_ROOT:-}" ]] ; then
  cd "${KOKORO_ARTIFACTS_DIR}/git/tink"
fi

./kokoro/testutils/copy_credentials.sh "java_src/testdata"
./kokoro/testutils/update_android_sdk.sh

pushd java_src
use_bazel.sh "$(cat .bazelversion)"
bazel build ...
bazel test --test_output=errors -- ...
popd

test_build_bazel_file
