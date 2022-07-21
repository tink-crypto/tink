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

# This script takes credentials injected into the environment via the Kokoro job
# configuration and copies them to the expected locations to facilitate
# continuous integration testing.
#
# Usage insructions:
#
#   ./kokoro/testutils/copy_credentials.sh <testdata dir>

if [[ -z "${KOKORO_ROOT}" ]]; then
  exit 0
fi

readonly TESTDATA_DIR="${1}"

if [[ -z "${TESTDATA_DIR}" ]]; then
  echo "Testdata directory must be set" >&2
  exit 1
fi

if [[ ! -d "${TESTDATA_DIR}" ]]; then
  echo "Testdata directory \"${TESTDATA_DIR}\" doesn't exist" >&2
  exit 1
fi

cp "${TINK_TEST_SERVICE_ACCOUNT}" "${TESTDATA_DIR}/gcp/credential.json"

# Create the different format for the AWS credentials
readonly AWS_KEY_ID="AKIATNYZMJOHVMN7MSYH"
readonly AWS_KEY="$(cat ${AWS_TINK_TEST_SERVICE_ACCOUNT})"

cat <<END > "${TESTDATA_DIR}/aws/credentials.ini"
[default]
aws_access_key_id = ${AWS_KEY_ID}
aws_secret_access_key = ${AWS_KEY}
END

cat <<END > "${TESTDATA_DIR}/aws/credentials.cred"
[default]
accessKey = ${AWS_KEY_ID}
secretKey = ${AWS_KEY}
END


cat <<END > "${TESTDATA_DIR}/aws/credentials.csv"
User name,Password,Access key ID,Secret access key,Console login link
tink-user1,,${AWS_KEY_ID},${AWS_KEY},https://235739564943.signin.aws.amazon.com/console
END
