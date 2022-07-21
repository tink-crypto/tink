#!/bin/bash
# Copyright 2022 Google LLC
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

# This scripts installs the protocol buffer compiler at a given version.
#
# NOTEs:
#   * If not running on Kokoro, this script will do nothing.
#   * This script MUST be sourced to update the environment of the calling
#     script.
#
# Usage:
#   source ./kokoro/testutils/install_protoc.sh [version]

readonly DEFAULT_PROTOC_VERSION="3.19.3"

install_temp_protoc() {
  local protoc_version="${1:-${DEFAULT_PROTOC_VERSION}}"
  local platform="$(uname | tr '[:upper:]' '[:lower:]')"
  local protoc_zip="protoc-${protoc_version}-linux-x86_64.zip"
  if [[ "${platform}" == 'darwin' ]]; then
    protoc_zip="protoc-${protoc_version}-osx-x86_64.zip"
  fi
  local protoc_url="https://github.com/protocolbuffers/protobuf/releases/download/v${protoc_version}/${protoc_zip}"
  local -r protoc_tmpdir="$(mktemp -dt tink-protoc.XXXXXX)"
  (
    cd "${protoc_tmpdir}"
    curl -OLsS "${protoc_url}"
    unzip "${protoc_zip}" bin/protoc
  )
  export PATH="${protoc_tmpdir}/bin:${PATH}"
}

if [[ -n "${KOKORO_ROOT:-}" ]]; then
  install_temp_protoc "$@"
fi
