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
cd ${KOKORO_ARTIFACTS_DIR}/git/tink

./kokoro/copy_credentials.sh

cd cc
use_bazel.sh $(cat .bazelversion)
bazel build ...
bazel test --test_output=errors -- ...

# Run build and tests with the BoringSSL FIPS module
bazel clean
APPEND_AFTER='workspace(name = "tink_cc")'
NUM_MATCHES="$(grep -c "${APPEND_AFTER}" WORKSPACE)"
if (( $? != 0 || NUM_MATCHES != 1)); then
  echo "ERROR: Could not patch WORKSPACE to build BoringSSL with FIPS module"
  exit 1
fi

mapfile LOCAL_FIPS_REPOSITORY <<EOM
local_repository(
  name = "boringssl",
  path = "third_party/boringssl_fips",
)
EOM

printf -v INSERT_TEXT '\\n%s' "${LOCAL_FIPS_REPOSITORY[@]//$'\n'/}"
sed -i.bak "/${APPEND_AFTER}/a \\${INSERT_TEXT}" WORKSPACE

bazel build --//config:use_only_fips=True --build_tag_filters=-requires_boringcrypto_update -- ...
bazel test --//config:use_only_fips=True --test_tag_filters=fips,-requires_boringcrypto_update -- ...

mv WORKSPACE.bak WORKSPACE
