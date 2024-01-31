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

ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64 | amd64) ARCH="amd64" ;;
  arm64 | aarch64) ARCH="arm64" ;;
  *)
    echo "PreconditionError: Unsupported architecture ${ARCH}" >&2
    exit 1
    ;;
esac
readonly ARCH

readonly VAULT_VERSION="1.15.5"
readonly VAULT_URL="https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_${PLATFORM}_${ARCH}.zip"
readonly VAULT_LINUX_AMD64_SAH256="6a370c7506a48c323743b0d81ebc6a4037ba1388c9838ef45f9eada53d7966e9"
readonly VAULT_LINUX_ARM64_SAH256="bfee22297a9812d703bb2b788b9fdc124b58a0ed07e50ffc74d29e526fb911bb"
readonly VAULT_DARWIN_AMD64_SAH256="606c6b740639c74c5fb8dc973a4ffdda15711a1b005eb90cb9ffcd16b7b548dd"
readonly VAULT_DARWIN_ARM64_SAH256="2a0fb5fb1e3e610327751ea13f85fc5526fbc703339767d87d1186a40db664ab"

readonly VAULT_INSTALL_DIR="$(mktemp -dt vault.XXXXXX)"
(
  cd "${VAULT_INSTALL_DIR}"
  curl -LsS "${VAULT_URL}" -o vault.zip
  SHA256=
  case "${PLATFORM}" in
    linux)
      SHA256="${VAULT_LINUX_AMD64_SAH256}"
      if [[ "${ARCH}" == "arm64" ]]; then
        SHA256="${VAULT_LINUX_ARM64_SAH256}"
      fi
      ;;
    darwin)
      SHA256="${VAULT_DARWIN_AMD64_SAH256}"
      if [[ "${ARCH}" == "arm64" ]]; then
        SHA256="${VAULT_DARWIN_ARM64_SAH256}"
      fi
      ;;
    *)
      echo "PreconditionError: Unsupported OS ${PLATFORM}" >&2
      exit 1
      ;;
  esac
  readonly SHA256
  echo "${SHA256} vault.zip" | sha256sum -c
  unzip vault.zip
)
export PATH="${VAULT_INSTALL_DIR}:${PATH}"

