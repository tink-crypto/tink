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

set -eu

if [ $# -lt 1 ]; then
  echo "usage $0 <version-name>"
  exit 1;
fi

version_name="$1"
shift 1

if [[ ! "${version_name}" =~ ^1\. ]]; then
  echo 'Version name must begin with "1."'
  exit 2
fi

if [[ "${version_name}" =~ " " ]]; then
  echo "Version name must not have any spaces"
  exit 3
fi

bash "$(dirname $0)/execute_deploy.sh" \
  "gpg:sign-and-deploy-file" \
  "${version_name}" \
  "-DrepositoryId=ossrh" \
  "-Durl=https://oss.sonatype.org/service/local/staging/deploy/maven2/" \
  "-X"
