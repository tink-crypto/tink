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

# Change to repo root
cd git*/tink

# Only in Kokoro environments.
if [[ -n "${KOKORO_ROOT}" ]]; then
  # TODO(b/73748835): Workaround on Kokoro.
  rm -f ~/.bazelrc

  use_bazel.sh latest || exit 1
fi

BAZEL_WRAPPER="${KOKORO_GFILE_DIR}/bazel_wrapper.py"
chmod +x "${BAZEL_WRAPPER}"

echo "using bazel binary: $(which bazel)"
"${BAZEL_WRAPPER}" version

time "${BAZEL_WRAPPER}" \
  --bazelrc="${KOKORO_GFILE_DIR}/bazel-rbe.bazelrc" \
  test \
  --config=remote \
  --incompatible_disable_deprecated_attr_params=false \
  --incompatible_depset_is_not_iterable=false  \
  --remote_accept_cached=true \
  --remote_local_fallback=false \
  -- \
  //tink/cc/...
