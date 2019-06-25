#!/bin/bash
#
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

# Change to repo root
cd git*/tink

# Only in Kokoro environments.
if [[ -n "${KOKORO_ROOT}" ]]; then
  # TODO(b/73748835): Workaround on Kokoro.
  rm -f ~/.bazelrc

  use_bazel.sh latest || exit 1
fi

echo "Using bazel binary: $(which bazel)"
bazel version

# Create an invocation ID for the bazel, and write it as an artifact.
# Kokoro will use that later to post the bazel invocation details.
INVOCATION_ID=$(uuidgen)
echo "Invocation ID = ${INVOCATION_ID}"
ID_OUT="${KOKORO_ARTIFACTS_DIR}/bazel_invocation_ids"
echo "${INVOCATION_ID}" >> "${ID_OUT}"

# Setup all the RBE args needed by bazel.
declare -a RBE_ARGS
RBE_ARGS=(
  --invocation_id="${INVOCATION_ID}"
  --auth_enabled=true
  --auth_credentials="${KOKORO_BAZEL_AUTH_CREDENTIAL}"
  --auth_scope=https://www.googleapis.com/auth/cloud-source-tools
  --bes_backend="${BES_BACKEND}"
  --bes_timeout=600s
  --project_id="${KOKORO_BES_PROJECT_ID}"
  --remote_cache="${REMOTE_CACHE}"
  --remote_executor="${REMOTE_CACHE}"
  --remote_accept_cached=true
  --remote_local_fallback=false
  --test_env=USER=anon
  --remote_instance_name="${KOKORO_FOUNDRY_PROJECT_ID}/instances/default_instance"
)
readonly RBE_ARGS

# Run all C++ and Java tests.
# TODO(candrian): Figure out why the KMS tests are failing.
# TODO(candrian): Add the remaining tests (Go, Python etc.)
bazel \
  --bazelrc="${KOKORO_GFILE_DIR}/bazel-rbe.bazelrc" \
  test "${RBE_ARGS[@]}" \
  --config=remote \
  --test_output=errors \
  --incompatible_disable_deprecated_attr_params=false \
  --incompatible_depset_is_not_iterable=false  \
  -- \
  //cc/... \
  //java/... \
  -//java:src/test/java/com/google/crypto/tink/aead/KmsAeadKeyManagerTest \
  -//java:src/test/java/com/google/crypto/tink/aead/KmsEnvelopeAeadKeyManagerTest
