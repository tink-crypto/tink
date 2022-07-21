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

# This scripts installs OpenSSL of a given version and SHA256. If the version is
# not specified, DEFAULT_OPENSSL_VERSION is used; similarly the digest is by
# default DEFAULT_OPENSSL_SHA256.
#
# NOTEs:
#   * If not running on Kokoro, this script will do nothing.
#   * This script MUST be sourced to update the environment of the calling
#     script.
#   * If a custom version is passed, the corresponding digest should be passed
#     too.
#
# Usage:
#   source ./kokoro/testutils/install_openssl.sh [version] [sha256]

readonly DEFAULT_OPENSSL_VERSION="1.1.1l"
readonly DEFAULT_OPENSSL_SHA256="0b7a3e5e59c34827fe0c3a74b7ec8baef302b98fa80088d7f9153aa16fa76bd1"

install_openssl() {
  local openssl_version="${1:-${DEFAULT_OPENSSL_VERSION}}"
  local openssl_sha256="${2:-${DEFAULT_OPENSSL_SHA256}}"
  local openssl_name="openssl-${openssl_version}"
  local openssl_archive="${openssl_name}.tar.gz"
  local openssl_url="https://www.openssl.org/source/${openssl_archive}"

  local openssl_tmpdir="$(mktemp -dt tink-openssl.XXXXXX)"
  (
    cd "${openssl_tmpdir}"
    curl -OLsS "${openssl_url}"
    echo "${openssl_sha256} ${openssl_archive}" | sha256sum -c

    tar xzf "${openssl_archive}"
    cd "${openssl_name}"
    ./config --prefix="${openssl_tmpdir}" --openssldir="${openssl_tmpdir}"
    make
    make install
  )
  export OPENSSL_ROOT_DIR="${openssl_tmpdir}"
  export PATH="${openssl_tmpdir}/bin:${PATH}"
}

if [[ -n "${KOKORO_ROOT:-}" ]]; then
  # If specifying the version, users must also specify the digest.
  if (( "$#" == 1 )); then
    echo \
      "The SHA256 digest must be provided too when specifying OpenSSL's version" \
      >&2
    exit 1
  fi
  install_openssl "$@"
fi
