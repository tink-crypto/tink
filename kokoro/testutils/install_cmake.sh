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

# This scripts installs CMake of a given version and SHA256. If the version is
# not specified, DEFAULT_CMAKE_VERSION is used; similarly the digest is by
# default DEFAULT_CMAKE_SHA256.
#
# NOTEs:
#   * If not running on Kokoro, this script will do nothing.
#   * This script MUST be sourced to update the environment of the calling
#     script.
#   * If a custom version is passed, the corresponding digest should be passed
#     too.
#
# Usage:
#   source ./kokoro/testutils/install_cmake.sh [version] [sha256]

readonly DEFAULT_CMAKE_VERSION="3.21.3"
readonly DEFAULT_CMAKE_SHA256="a19aa9fcf368e9d923cdb29189528f0fe00a0d08e752ba4e547af91817518696"

install_cmake() {
  local cmake_version="${1:-${DEFAULT_CMAKE_VERSION}}"
  local cmake_sha256="${2:-${DEFAULT_CMAKE_SHA256}}"
  local cmake_name="cmake-${cmake_version}-linux-x86_64"
  local cmake_archive="${cmake_name}.tar.gz"
  local cmake_url="https://github.com/Kitware/CMake/releases/download/v${cmake_version}/${cmake_archive}"
  local cmake_tmpdir="$(mktemp -dt tink-cmake.XXXXXX)"
  (
    cd "${cmake_tmpdir}"
    curl -OLsS "${cmake_url}"
    echo "${cmake_sha256} ${cmake_archive}" | sha256sum -c

    tar xzf "${cmake_archive}"
  )
  export PATH="${cmake_tmpdir}/${cmake_name}/bin:${PATH}"
}

if [[ -n "${KOKORO_ROOT:-}" ]]; then
  # If specifying the version, users must also specify the digest.
  if (( "$#" == 1 )); then
    echo \
      "The SHA256 digest must be provided too when specifying CMake's version" \
      >&2
    exit 1
  fi
  install_cmake "$@"
fi
