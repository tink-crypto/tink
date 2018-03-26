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

#!/bin/bash

# Fail on any error.
set -e

# Display commands to stderr.
set -x

echo -e "Publishing Maven snapshot...\n"

bash $(dirname $0)/execute-deploy.sh \
  "deploy:deploy-file" \
  "HEAD-SNAPSHOT" \
  -DrepositoryId=ossrh \
  -Durl=https://oss.sonatype.org/content/repositories/snapshots \
  --settings=$(dirname $0)/settings.xml

echo -e "Published Maven snapshot"
