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
# configuration and copies them to the expected locations.
#
# The second argument indicates whether all KMS service credentials should be
# copied (all) or only credentials for a specific KMS service (gcp|aws).
#
# Usage insructions:
#
#   ./kokoro/testutils/copy_credentials.sh <testdata dir> <all|aws|gcp>
#

TESTDATA_DIR=
KMS_SERVICE=

#######################################
# Process command line arguments.
#
# Globals:
#   TESTDATA_DIR
#   KMS_SERVICE
#######################################
process_args() {
  TESTDATA_DIR="$1"
  readonly TESTDATA_DIR
  KMS_SERVICE="$2"
  readonly KMS_SERVICE

  if [[ -z "${TESTDATA_DIR}" ]]; then
    echo "Testdata directory must be set" >&2
    exit 1
  fi

  if [[ ! -d "${TESTDATA_DIR}" ]]; then
    echo "Testdata directory \"${TESTDATA_DIR}\" doesn't exist" >&2
    exit 1
  fi

  if [[ -z "${KMS_SERVICE}" ]]; then
    echo "KMS service must be specified" >&2
    exit 1
  fi
}

#######################################
# Copy GCP credentials.
#
# Globals:
#   TESTDATA_DIR
#   TINK_TEST_SERVICE_ACCOUNT
#######################################
copy_gcp_credentials() {
  cp "${TINK_TEST_SERVICE_ACCOUNT}" "${TESTDATA_DIR}/gcp/credential.json"
}

#######################################
# Copy AWS credentials.
#
# Globals:
#   TESTDATA_DIR
#   AWS_TINK_TEST_SERVICE_ACCOUNT
#######################################
copy_aws_credentials() {
  # Create the different format for the AWS credentials
  local -r aws_key_id="AKIATNYZMJOHVMN7MSYH"
  local -r aws_key="$(cat ${AWS_TINK_TEST_SERVICE_ACCOUNT})"

  cat <<END > "${TESTDATA_DIR}/aws/credentials.ini"
[default]
aws_access_key_id = ${aws_key_id}
aws_secret_access_key = ${aws_key}
END

  cat <<END > "${TESTDATA_DIR}/aws/credentials.cred"
[default]
accessKey = ${aws_key_id}
secretKey = ${aws_key}
END

  cat <<END > "${TESTDATA_DIR}/aws/credentials.csv"
User name,Password,Access key ID,Secret access key,Console login link
tink-user1,,${aws_key_id},${aws_key},https://235739564943.signin.aws.amazon.com/console
END
}

main() {
  if [[ -z "${KOKORO_ROOT}" ]]; then
    exit 0
  fi

  process_args "$@"

  case "${KMS_SERVICE}" in
    aws)
      copy_aws_credentials
      ;;
    gcp)
      copy_gcp_credentials
      ;;
    all)
      copy_aws_credentials
      copy_gcp_credentials
      ;;
    *)
      echo "Invalid KMS service \"${KMS_SERVICE}\"" >&2
      exit 1
  esac
}

main "$@"
