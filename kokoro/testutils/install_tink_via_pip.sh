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

# This scripts installs Tink for Python and its dependencies using Pip.
# Tink's root folder must be specified.
#
# NOTE: If not running on Kokoro, this script will do nothing.

set -eo pipefail

usage() {
  cat <<EOF
Usage:  $0 <path to tink python root>
  -h: Help. Print this usage information.
EOF
  exit 1
}

TINK_PY_ROOT_DIR=

#######################################
# Process command line arguments.
#######################################
process_args() {
  # Parse options.
  while getopts "h" opt; do
    case "${opt}" in
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))
  TINK_PY_ROOT_DIR="$1"
  if [[ -z "${TINK_PY_ROOT_DIR}" ]]; then
    echo "ERROR: The root folder of Tink Python must be specified" >&2
    usage
  fi
  readonly TINK_PY_ROOT_DIR
}


main() {
  process_args "$@"
  if [[ -z "${KOKORO_ROOT:-}" ]] ; then
    echo "Not running on Kokoro, skip installing tink-py"
    return
  fi
  (
    cd "${TINK_PY_ROOT_DIR}"
    local -r platform="$(uname | tr '[:upper:]' '[:lower:]')"
    local -a pip_flags
    if [[ "${platform}" == 'darwin' ]]; then
      # On MacOS we need to use the --user flag as otherwise pip will complain
      # about permissions.
      pip_flags=( --user )
    fi
    readonly pip_flags

    python3 -m pip install "${pip_flags[@]}" --upgrade pip setuptools
    # Install Tink Python requirements.
    python3 -m pip install "${pip_flags[@]}" --require-hashes -r requirements.txt
    # Install Tink Python
    python3 -m pip install "${pip_flags[@]}" .
  )
}

main "$@"
