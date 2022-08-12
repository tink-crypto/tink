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

readonly DEFAULT_DIR="$(dirname -- $0)"

readonly DEFAULT_TESTDATA_PREFIX="${DEFAULT_DIR}/testdata/\
replace_http_archive_with_local_repository_test_"

readonly CLI="${1:-"${DEFAULT_DIR}/\
replace_http_archive_with_local_repository.py"}"

readonly TEST_UTILS="${2:-${DEFAULT_DIR}/test_utils.sh}"

readonly GENERAL_TEST_EXPECTED="${3:-"${DEFAULT_TESTDATA_PREFIX}\
general_test_expected.txt"}"

readonly GENERAL_TEST_INPUT="${4:-"${DEFAULT_TESTDATA_PREFIX}\
general_test_input.txt"}"

readonly HTTP_ARCHIVE_DELETED_EXPECTED="${5:-"${DEFAULT_TESTDATA_PREFIX}\
http_archive_deleted_expected.txt"}"

readonly HTTP_ARCHIVE_DELETED_INPUT="${6:-"${DEFAULT_TESTDATA_PREFIX}\
http_archive_deleted_input.txt"}"

readonly HTTP_ARCHIVE_NOT_DELETED_EXPECTED="${7:-"${DEFAULT_TESTDATA_PREFIX}\
http_archive_not_deleted_expected.txt"}"

readonly HTTP_ARCHIVE_NOT_DELETED_INPUT="${8:-"${DEFAULT_TESTDATA_PREFIX}\
http_archive_not_deleted_input.txt"}"

# Load the test library.
source "${TEST_UTILS}"

# Test that http_archive entries are correctly replaced.
#
test_ReplaceHttpArchiveWithLocalRepositoryTest_GeneralTest() {
  ls "${TEST_CASE_TMPDIR}"
  cp "${GENERAL_TEST_INPUT}" "${TEST_CASE_TMPDIR}/input.txt"
  "${CLI}" -f "${TEST_CASE_TMPDIR}/input.txt" -t "/tmp/git"
  ASSERT_CMD_SUCCEEDED
  ASSERT_FILE_EQUALS "${TEST_CASE_TMPDIR}/input.txt" \
    "${GENERAL_TEST_EXPECTED}"
}

# Test that loading http_archive isn't deleted because there is at least another
# http_archive entry in the WORKSPACE file.
test_ReplaceHttpArchiveWithLocalRepositoryTest_\
HttpArchiveIsNotDeletedBecauseOtherHttpArchiveIsPresent() {
  cp "${HTTP_ARCHIVE_NOT_DELETED_INPUT}" "${TEST_CASE_TMPDIR}/input.txt"
  "${CLI}" -f "${TEST_CASE_TMPDIR}/input.txt" -t "/tmp/git"
  ASSERT_CMD_SUCCEEDED
  ASSERT_FILE_EQUALS "${TEST_CASE_TMPDIR}/input.txt" \
    "${HTTP_ARCHIVE_NOT_DELETED_EXPECTED}"
}

# Test that loading http_archive is deleted because there are no other uses of
# http_archive.
test_ReplaceHttpArchiveWithLocalRepositoryTest_\
HttpArchiveIsDeletedBecauseOtherHttpArchiveIsComment() {
  cp "${HTTP_ARCHIVE_DELETED_INPUT}" "${TEST_CASE_TMPDIR}/input.txt"
  # "${CLI}" -f "${TEST_CASE_TMPDIR}/input.txt" -t "/tmp/git"
  ASSERT_CMD_SUCCEEDED
  ASSERT_FILE_EQUALS "${TEST_CASE_TMPDIR}/input.txt" \
    "${HTTP_ARCHIVE_DELETED_EXPECTED}"
}

main() {
  run_all_tests "$@"
}

main "$@"
