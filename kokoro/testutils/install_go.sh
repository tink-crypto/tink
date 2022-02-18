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

# This script installs a recent version of Go into a temporary directory. The Go
# bin directory is then added to the PATH environment variable.
#
# NOTE: This script MUST be sourced to update the environment of the calling
# script.
#
# Usage instructions:
#
#  source ./kokoro/testutils/install_go.sh

install_temp_go() {
  local -r go_version="1.16.14"

  local -r platform="$(uname | tr '[:upper:]' '[:lower:]')"
  local go_platform
  case "${platform}" in
    'linux')
      go_platform='linux-amd64'
      ;;
    'darwin')
      go_platform='darwin-amd64'
      ;;
    *)
      echo "Unsupported platform, unable to install Go."
      exit 1
      ;;
  esac
  readonly go_platform

  local -r go_archive="go${go_version}.${go_platform}.tar.gz"
  local -r go_url="https://go.dev/dl/${go_archive}"

  local -r go_tmpdir=$(mktemp -dt tink-go.XXXXXX)
  (
    cd "${go_tmpdir}"
    curl -OLsS "${go_url}"
    tar -xzf "${go_archive}"
  )

  export PATH="${go_tmpdir}/go/bin:${PATH}"
}

if [[ -n "${KOKORO_ROOT}" ]] ; then
  install_temp_go
fi
