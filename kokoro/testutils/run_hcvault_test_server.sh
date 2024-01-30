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

# This script runs a local test HashiCorp Vault server in developer mode.
#
# NOTE: `vault` must be already installed.

readonly PORT="8200"
readonly VAULT_TOKEN_FILE="${HOME}/.vault-token"
readonly VAULT_TMP_TLS_DIR="$(mktemp -dt vault_tls.XXXXXX)"
rm -rf "${VAULT_TOKEN_FILE}"

# The following code starts a local hashicorp vault server in dev mode in
# the background. See:
# https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-dev-server
# https://developer.hashicorp.com/vault/docs/commands
export VAULT_API_ADDR="https://127.0.0.1:${PORT}"
vault server -dev -dev-tls -dev-tls-cert-dir="${VAULT_TMP_TLS_DIR}" &

# Wait until VAULT_TOKEN_FILE is created up to a timeout.
i=0
readonly TIMEOUT=60
until [[ -f "${VAULT_TOKEN_FILE}" ]] || (( i >= TIMEOUT )); do
  echo "File ${VAULT_TOKEN_FILE} not yet ready."
  sleep 1
  i="$(( i + 1 ))"
done
if (( i >= TIMEOUT )); then
  echo "FileNotFoundError: ${VAULT_TOKEN_FILE} not found after more than ${TIMEOUT} seconds" >&2
  ls -al "${HOME}"
  exit 1
fi

export VAULT_TOKEN="$(cat "${VAULT_TOKEN_FILE}")"
export VAULT_SKIP_VERIFY=true
export VAULT_ADDR="https://127.0.0.1:${PORT}"
export VAULT_CACERT="${VAULT_TMP_TLS_DIR}/vault-ca.pem"

# Enable the transit secrets engine. See:
# https://developer.hashicorp.com/vault/tutorials/encryption-as-a-service/eaas-transit
vault secrets enable transit
