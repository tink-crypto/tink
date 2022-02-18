#!/bin/bash
# Copyright 2021 Google LLC
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

if [[ -n "${KOKORO_ROOT}" ]]; then
  # The env variable is set up in common.cfg.
  cp "${TINK_TEST_SERVICE_ACCOUNT}" "testdata/credential.json"

  # Create the different format for the AWS credentials
  AWS_KEY_ID="AKIATNYZMJOHVMN7MSYH"
  AWS_KEY=$(cat ${AWS_TINK_TEST_SERVICE_ACCOUNT})

  printf "[default]\naws_access_key_id = ${AWS_KEY_ID}\naws_secret_access_key = ${AWS_KEY}\n" > testdata/aws_credentials_cc.txt
  printf "[default]\naccessKey = ${AWS_KEY_ID}\nsecretKey = ${AWS_KEY}\n" > testdata/credentials_aws.cred
  printf "[default]\naws_access_key_id = ${AWS_KEY_ID}\naws_secret_access_key = ${AWS_KEY}\n" > testdata/credentials_aws.ini
  printf "User name,Password,Access key ID,Secret access key,Console login link\ntink-user1,,${AWS_KEY_ID},${AWS_KEY},https://235739564943.signin.aws.amazon.com/console\n" > testdata/credentials_aws.csv
fi
