#!/bin/bash

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

# Fail on any error.
set -e

# Display commands to stderr.
set -x

usage() {
  echo "Usage: $0 [-dlh]"
  echo "  -d: Dry run. Only execute idempotent commands (default: FALSE)."
  echo "  -l: Local. Publish to local Maven repository (default: FALSE)."
  echo "  -h: Help. Print this usage information."
  exit 1
}

DRY_RUN="false"
LOCAL="false"

while getopts "dlh" opt; do
  case "${opt}" in
    d) DRY_RUN="true" ;;
    l) LOCAL="true" ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

readonly DRY_RUN
readonly LOCAL

declare -a FLAGS
if [[ "${DRY_RUN}" == "true" ]]; then
  FLAGS+=( -d )
fi
readonly FLAGS

if [[ "${LOCAL}" == "true" ]]; then
  echo "Publishing local Maven snapshot..."
  bash "$(dirname $0)/execute_deploy.sh" "${FLAGS[@]}" "install" "HEAD"
else
  echo "Publishing Maven snapshot...\n"
  bash "$(dirname $0)/execute_deploy.sh" "${FLAGS[@]}" "snapshot" "HEAD"
fi

echo "Finished publishing Maven snapshot."
