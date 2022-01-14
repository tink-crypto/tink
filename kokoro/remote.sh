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

  use_bazel.sh $(cat .bazelversion)

  ./kokoro/copy_credentials.sh
  ./kokoro/update_android_sdk.sh
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
# The kokoro env variables are set in tink/kokoro/presubmit-remote.cfg.
declare -a RBE_ARGS
RBE_ARGS=(
  --invocation_id="${INVOCATION_ID}"
  --auth_enabled=true
  --auth_credentials="${KOKORO_BAZEL_AUTH_CREDENTIAL}"
  --auth_scope=https://www.googleapis.com/auth/cloud-source-tools
  --bes_backend="${KOKORO_BES_BACKEND_ADDRESS}"
  --bes_timeout=600s
  --project_id="${KOKORO_BES_PROJECT_ID}"
  --remote_cache="${KOKORO_FOUNDRY_BACKEND_ADDRESS}"
  --remote_executor="${KOKORO_FOUNDRY_BACKEND_ADDRESS}"
  --test_env=USER=anon
  --remote_instance_name="${KOKORO_FOUNDRY_PROJECT_ID}/instances/default_instance"
)
readonly RBE_ARGS

RBE_BAZELRC="$PWD/tools/remote_build_execution/bazel-rbe.bazelrc"
echo "RBE_BAZELRC: $RBE_BAZELRC"

# TODO(b/141297103): enable Python
# TODO(b/143102587): enable Javascript

readonly TINK_BASE_DIR="${PWD}"

# Build and test C++.
cd "${TINK_BASE_DIR}/cc/"
time bazel --bazelrc="$RBE_BAZELRC" \
  build "${RBE_ARGS[@]}" \
  --config=remote \
  --build_tag_filters=-no_rbe \
  -- ...

time bazel --bazelrc="$RBE_BAZELRC" \
  test "${RBE_ARGS[@]}" \
  --config=remote \
  --test_output=errors \
  --test_tag_filters=-no_rbe \
  --jvmopt=-Drbe=1 \
  -- ...

# Build and test Tink C++ AWS-KMS.
cd "${TINK_BASE_DIR}/kms/cc/aws/"
time bazel --bazelrc="$RBE_BAZELRC" \
  build "${RBE_ARGS[@]}" \
  --config=remote \
  --build_tag_filters=-no_rbe \
  -- ...

time bazel --bazelrc="$RBE_BAZELRC" \
  test "${RBE_ARGS[@]}" \
  --config=remote \
  --test_output=errors \
  --test_tag_filters=-no_rbe \
  --jvmopt=-Drbe=1 \
  -- ...

# Build and test Java.
cd "${TINK_BASE_DIR}/java_src"
time bazel --bazelrc="$RBE_BAZELRC" \
  build "${RBE_ARGS[@]}" \
  --config=remote \
  --build_tag_filters=-no_rbe \
  -- ...

time bazel --bazelrc="$RBE_BAZELRC" \
  test "${RBE_ARGS[@]}" \
  --config=remote \
  --test_output=errors \
  --test_tag_filters=-no_rbe \
  --jvmopt=-Drbe=1 \
  -- ...

# Build and test Go.
cd "${TINK_BASE_DIR}/go"
time bazel --bazelrc="$RBE_BAZELRC" \
  build "${RBE_ARGS[@]}" \
  --config=remote \
  --build_tag_filters=-no_rbe \
  -- ...

time bazel --bazelrc="$RBE_BAZELRC" \
  test "${RBE_ARGS[@]}" \
  --config=remote \
  --test_output=errors \
  --test_tag_filters=-no_rbe \
  --jvmopt=-Drbe=1 \
  -- ...

# TODO(b/141297103): Python causes this to fail on remote
# # Build tools and run cross-language tests.
# cd ../tools
# time bazel --bazelrc="$RBE_BAZELRC" \
#   build "${RBE_ARGS[@]}" \
#   --config=remote \
#   --build_tag_filters=-no_rbe \
#   -- ...
#
# time bazel --bazelrc="$RBE_BAZELRC" \
#   test "${RBE_ARGS[@]}" \
#   --config=remote \
#   --test_output=errors \
#   --test_tag_filters=-no_rbe \
#   --jvmopt=-Drbe=1 \
#   -- ...

# We don't currently run TypeScript/JavaScript tests remotely because they
# require libx11-xcb-dev in order to bring up browsers.
