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

# If we are running on Kokoro cd into the repository.
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  cd "${KOKORO_ARTIFACTS_DIR}/git/tink"
  use_bazel.sh "$(cat python/.bazelversion)"
fi

./kokoro/testutils/copy_credentials.sh "python/testdata" "all"
./kokoro/testutils/upgrade_gcc.sh
# Sourcing required to update callers environment.
source ./kokoro/testutils/install_python3.sh
source ./kokoro/testutils/install_protoc.sh
source ./kokoro/testutils/install_vault.sh
source ./kokoro/testutils/run_hcvault_test_server.sh

# Install a test transit key.
vault write -f transit/keys/key-1

./kokoro/testutils/install_tink_via_pip.sh -a "${PWD}/python"

# Get root certificates for gRPC
curl -OLsS https://raw.githubusercontent.com/grpc/grpc/master/etc/roots.pem
export GRPC_DEFAULT_SSL_ROOTS_FILE_PATH="${PWD}/roots.pem"

# Set path to the Tink Python folder
export TINK_PYTHON_ROOT_PATH="${PWD}/python"

# Run Python tests directly so the package is used.
# We exclude tests in tink/cc/pybind: they are implementation details and may
# depend on a testonly shared object.
find python/tink/ -not -path "*cc/pybind*" -type f -name "*_test.py" -print0 \
  | xargs -0 -n1 python3
