#!/bin/bash
# Copyright 2020 Google LLC
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

readonly REPO_DIR="${TEST_SRCDIR}"
readonly TOOLS_DIR="${REPO_DIR}/tools"
readonly TEST_UTIL="${TOOLS_DIR}/testing/cross_language/test_util.sh"

# Paths to AEAD CLI utilities.
readonly CC_AEAD_CLI="${TOOLS_DIR}/testing/cc/aead_cli_cc"
readonly GO_AEAD_CLI="${TOOLS_DIR}/testing/go/aead_cli_go"
readonly JAVA_AEAD_CLI="${TOOLS_DIR}/testing/aead_cli_java"
readonly PY_AEAD_CLI="${TOOLS_DIR}/testing/python/aead_cli_python"

# Modify the following variables to alter the set of languages and key formats
# tested.
declare -a ENCRYPT_CLIS
ENCRYPT_CLIS=(
  "${GO_AEAD_CLI}"
  "${JAVA_AEAD_CLI}"
  "${CC_AEAD_CLI}"
  "${PY_AEAD_CLI}"
)
readonly ENCRYPT_CLIS

declare -a DECRYPT_CLIS
DECRYPT_CLIS=(
  "${GO_AEAD_CLI}"
  "${JAVA_AEAD_CLI}"
  "${CC_AEAD_CLI}"
  "${PY_AEAD_CLI}"
)
readonly DECRYPT_CLIS

declare -a KEY_TEMPLATES
KEY_TEMPLATES=(
  AES128_GCM
  AES128_CTR_HMAC_SHA256
)
readonly KEY_TEMPLATES

# Root certificates for GRPC.
# (https://github.com/grpc/grpc/blob/master/doc/environment_variables.md)
export GRPC_DEFAULT_SSL_ROOTS_FILE_PATH="${TEST_SRCDIR}/google_root_pem/file/downloaded"

source "${TEST_UTIL}" || exit 1

#######################################
# Execute cross-language AEAD envelope encryption tests.
# Globals:
#   ENCRYPT_CLIS
#   DECRYPT_CLIS
#   KEY_TEMPLATES
# Arguments:
#   A name which describes the test.
#   The name of a command/function to generate the keyset.
#######################################
aead_envelope_test() {
  local test_name="$1"
  local keyset_function="$2"

  echo "############ starting test ${test_name} for the following templates:"
  echo "${KEY_TEMPLATES}"
  for key_template in "${KEY_TEMPLATES[@]}"
  do
    echo "## TEST for key template ${key_template}"
    for encrypt_cli in "${ENCRYPT_CLIS[@]}"
    do
      local test_instance="${test_name}_${key_template}"
      local encrypt_cli_name="$(basename "${encrypt_cli}")"

      "${keyset_function}" \
        "${test_instance}_ENCRYPT_${encrypt_cli_name}" \
        "${key_template}"
      generate_plaintext "${test_instance}"

      local encrypted_prefix="${test_instance}}_ENCRYPT_${encrypt_cli_name}"
      local encrypted_file="${TEST_TMPDIR}/${encrypted_prefix}_encrypted.bin"
      local associated_data_file="${encrypted_prefix}_aad.bin"
      echo "AAD for ${test_instance} using ${encrypt_cli_name} for encryption" \
          > "${associated_data_file}"

      echo "## ENCRYPTING using ${encrypt_cli_name}"
      "${encrypt_cli}" \
        "${aws_keyset_file}" \
        "encrypt" \
        "${plaintext_file}" \
        "${associated_data_file}" \
        "${encrypted_file}" \
        || exit 1

      assert_files_different "${plaintext_file}" "${encrypted_file}"

      for decrypt_cli in "${DECRYPT_CLIS[@]}"
      do
        local decrypt_cli_name="$(basename "${decrypt_cli}")"
        local decrypted_prefix="${encrypted_prefix}_DECRYPT_${decrypted_cli_name}"
        local decrypted_file="${TEST_TMPDIR}/${decrypted_prefix}_decrypted.bin"

        echo "## DECRYPTING using ${decrypt_cli_name}"
        "${decrypt_cli}" \
          "${aws_keyset_file}" \
          "decrypt" \
          "${encrypted_file}" \
          "${associated_data_file}" \
          "${decrypted_file}" \
          || exit 1

        assert_files_equal "${plaintext_file}" "${decrypted_file}"
      done
    done
  done
}

main() {
  aead_envelope_test "aead-envelope-aws-test" generate_aws_keyset
  aead_envelope_test "aead-envelope-gcp-test" generate_gcp_keyset
}

main "$@"
