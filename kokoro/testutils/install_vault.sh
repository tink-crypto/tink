#!/bin/bash
# Copyright 2024 Google LLC
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

# Installs the `vault` CLI tool.
set -eou pipefail

readonly PLATFORM="$(uname | tr '[:upper:]' '[:lower:]')"

readonly VAULT_VERSION="1.15.4"
readonly VAULT_URL="https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_${PLATFORM}_amd64.zip"
readonly VAULT_LINUX_SAH256="f42f550713e87cceef2f29a4e2b754491697475e3d26c0c5616314e40edd8e1b"
readonly VAULT_DARWIN_SAH256="a9d7c6e76d7d5c9be546e9a74860b98db6486fc0df095d8b00bc7f63fb1f6c1c"

readonly VAULT_INSTALL_DIR="$(mktemp -dt vault.XXXXXX)"
(
  cd "${VAULT_INSTALL_DIR}"
  curl -LsS "${VAULT_URL}" -o vault.zip
  SHA256="${VAULT_LINUX_SAH256}"
  if [[ "${PLATFORM}" == "darwin" ]]; then
    SHA256="${VAULT_DARWIN_SAH256}"
  fi
  readonly SHA256
  echo "${SHA256} vault.zip" | sha256sum -c
  unzip vault.zip
)
export PATH="${VAULT_INSTALL_DIR}:${PATH}"

