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

# Process flags.

DRY_RUN="false"
LOCAL="false"

while getopts "dlh" opt; do
  case "${opt}" in
    d) DRY_RUN="true" ;;
    l) LOCAL="true" ;;
    h) usage ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

readonly DRY_RUN
readonly LOCAL

declare -a COMMON_FLAGS
if [[ "${DRY_RUN}" == "true" ]]; then
  COMMON_FLAGS+=( -d )
fi
readonly COMMON_FLAGS

if [[ "${LOCAL}" == "true" ]]; then
  echo -e "Publishing local Maven snapshot...\n"
  bash "$(dirname $0)/execute_deploy.sh" "${COMMON_FLAGS[@]}" -l \
    "install:install-file" \
    "HEAD-SNAPSHOT"
else
  echo -e "Publishing Maven snapshot...\n"
  bash "$(dirname $0)/execute_deploy.sh" "${COMMON_FLAGS[@]}" \
    "deploy:deploy-file" \
    "HEAD-SNAPSHOT" \
    "-DrepositoryId=ossrh" \
    "-Durl=https://oss.sonatype.org/content/repositories/snapshots" \
    "--settings=../$(dirname $0)/settings.xml"
fi

echo -e "Finished publishing Maven snapshot."
