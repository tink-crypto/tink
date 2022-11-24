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

DEFAULT_DIR="$(pwd)"
if [[ -n "${TEST_SRCDIR}" ]]; then
  DEFAULT_DIR="${TEST_SRCDIR}/google3"
fi
readonly DEFAULT_DIR
readonly CLI="${DEFAULT_DIR}/${1:-"create_github_release.sh"}"
readonly TEST_UTILS="${DEFAULT_DIR}/${2:-test_utils.sh}"

# Load the test library.
source "${TEST_UTILS}"

test_CreateGithubReleaseTest_CreateReleaseBranchMinorSucceeds() {
  cd "${TEST_CASE_TMPDIR}"
  local -r expected_git_cmds_file="${TEST_CASE_TMPDIR}/expected_cmds.txt"
  cat << EOF > ${expected_git_cmds_file}
git ls-remote ssh://git@github.com/tink-crypto/some-repo
git clone ssh://git@github.com/tink-crypto/some-repo
git branch 1.6
git push origin 1.6
git checkout 1.6
git tag -a v1.6.0 -m some-repo version 1.6.0
git push origin v1.6.0
EOF

  local -r actual_git_cmds_file="${TEST_CASE_TMPDIR}/actual_git_cmds_file.txt"
  # Mock git command.
  git() {
    local -r command="$1"
    shift 1
    cmd_and_args="git ${command} $@"
    echo "${cmd_and_args}" >> "${actual_git_cmds_file}"
    case "${command}" in
      "ls-remote")
        cat << EOF
6c68b48c884e0aeb983b8864f35187d9584d0d74        HEAD
6c68b48c884e0aeb983b8864f35187d9584d0d74        refs/heads/main
EOF
        ;;
      "clone")
        local -r repo_name="${1##*/}"
        mkdir "${repo_name}"
        ;;
      *)
        # Do nothing
        ;;
    esac
  }
  # Run this in the caller's environment.
  (
    source "${CLI}" -r 1.6.0 some-repo &> /dev/null
  )
  ASSERT_CMD_SUCCEEDED
  ASSERT_FILE_EQUALS "${actual_git_cmds_file}" "${expected_git_cmds_file}"
}

test_CreateGithubReleaseTest_CreateReleaseBranchMinorWithCommitSucceeds() {
  cd "${TEST_CASE_TMPDIR}"
  local -r expected_git_cmds_file="${TEST_CASE_TMPDIR}/expected_cmds.txt"
  cat << EOF > ${expected_git_cmds_file}
git ls-remote ssh://git@github.com/tink-crypto/some-repo
git clone ssh://git@github.com/tink-crypto/some-repo
git branch 1.6 6c68b48c884e0aeb983b8864f35187d9584d0d74
git push origin 1.6
git checkout 1.6
git tag -a v1.6.0 -m some-repo version 1.6.0
git push origin v1.6.0
EOF
  local -r actual_git_cmds_file="${TEST_CASE_TMPDIR}/actual_git_cmds_file.txt"
  # Mock git command.
  git() {
    local -r command="$1"
    shift 1
    cmd_and_args="git ${command} $@"
    echo "${cmd_and_args}" >> "${actual_git_cmds_file}"
    case "${command}" in
      "ls-remote")
        cat << EOF
6c68b48c884e0aeb983b8864f35187d9584d0d74        HEAD
6c68b48c884e0aeb983b8864f35187d9584d0d74        refs/heads/main
EOF
        ;;
      "clone")
        local -r repo_name="${1##*/}"
        mkdir "${repo_name}"
        ;;
      *)
        # Do nothing
        ;;
    esac
  }

  # Run this in the caller's environment.
  (
    source "${CLI}" -r -c 6c68b48c884e0aeb983b8864f35187d9584d0d74 1.6.0 \
      some-repo &> /dev/null
  )
  ASSERT_CMD_SUCCEEDED
  ASSERT_FILE_EQUALS "${actual_git_cmds_file}" "${expected_git_cmds_file}"
}

# Tests that creating a patch release succeeds; the commit parameter is ignored.
test_CreateGithubReleaseTest_CreateReleaseBranchPatchSucceeds() {
  cd "${TEST_CASE_TMPDIR}"
  local -r expected_git_cmds_file="${TEST_CASE_TMPDIR}/expected_cmds.txt"
  cat << EOF > ${expected_git_cmds_file}
git ls-remote ssh://git@github.com/tink-crypto/some-repo
git clone ssh://git@github.com/tink-crypto/some-repo
git checkout 1.6
git tag -a v1.6.2 -m some-repo version 1.6.2
git push origin v1.6.2
EOF
  local -r actual_git_cmds_file="${TEST_CASE_TMPDIR}/actual_git_cmds_file.txt"
  # Mock git command.
  git() {
    local -r command="$1"
    shift 1
    cmd_and_args="git ${command} $@"
    echo "${cmd_and_args}" >> "${actual_git_cmds_file}"
    case "${command}" in
      "ls-remote")
        cat << EOF
6c68b48c884e0aeb983b8864f35187d9584d0d74        HEAD
6c68b48c884e0aeb983b8864f35187d9584d0d74        refs/heads/main
9940095f3081a116fa7a1337ad5ba27a3ccc59fe        refs/heads/1.6
EOF
        ;;
      "clone")
        local -r repo_name="${1##*/}"
        mkdir "${repo_name}"
        ;;
      *)
        # Do nothing.
        ;;
    esac
  }

  # Run this in the caller's environment.
  (
    source "${CLI}" -r -c 6c68b48c884e0aeb983b8864f35187d9584d0d74 1.6.2 \
      some-repo &> /dev/null
  )
  ASSERT_CMD_SUCCEEDED
  ASSERT_FILE_EQUALS "${actual_git_cmds_file}" "${expected_git_cmds_file}"
}

test_CreateGithubReleaseTest_CreateReleaseFailsWhenCloneFails() {
  cd "${TEST_CASE_TMPDIR}"
  local -r expected_git_cmds_file="${TEST_CASE_TMPDIR}/expected_cmds.txt"
  cat << EOF > ${expected_git_cmds_file}
git ls-remote ssh://git@github.com/tink-crypto/some-repo
git clone ssh://git@github.com/tink-crypto/some-repo
EOF
  local actual_git_cmds_file="${TEST_CASE_TMPDIR}/actual_cmds.txt"
  # Mock git command.
  git() {
    local -r command="$1"
    shift 1
    cmd_and_args="git ${command} $@"
    echo "${cmd_and_args}" >> "${actual_git_cmds_file}"
    case "${command}" in
      "ls-remote")
        cat << EOF
6c68b48c884e0aeb983b8864f35187d9584d0d74        HEAD
6c68b48c884e0aeb983b8864f35187d9584d0d74        refs/heads/main
EOF
        ;;
      "clone")
        return 1
        ;;
      *)
        # Do nothing.
        ;;
    esac
  }

  # Run this in a subshell to prevent exiting on failure.
  (
    source "${CLI}" -r 1.6.2 some-repo &> /dev/null
  )
  ASSERT_CMD_FAILED
  ASSERT_FILE_EQUALS "${actual_git_cmds_file}" "${expected_git_cmds_file}"
}

test_CreateGithubReleaseTest_CreateReleaseFailsIfReleaseTagAlreadyExists() {
  cd "${TEST_CASE_TMPDIR}"
  local -r expected_git_cmds_file="${TEST_CASE_TMPDIR}/expected_cmds.txt"
  cat << EOF > ${expected_git_cmds_file}
git ls-remote ssh://git@github.com/tink-crypto/some-repo
EOF
  local actual_git_cmds_file="${TEST_CASE_TMPDIR}/actual_cmds.txt"
  # Mock git command.
  git() {
    local -r command="$1"
    shift 1
    cmd_and_args="git ${command} $@"
    echo "${cmd_and_args}" >> "${actual_git_cmds_file}"
    case "${command}" in
      "ls-remote")
        cat << EOF
6c68b48c884e0aeb983b8864f35187d9584d0d74        HEAD
6c68b48c884e0aeb983b8864f35187d9584d0d74        refs/heads/main
112a7d3a0453a1d926448519f94fe5a91c69be45        refs/heads/1.6
8c266441044c4dfaf7560e21663a8037043b750b        refs/tags/v1.6.2
195ec3c1edeee8877ab5dc287f95c4402e3fb510        refs/tags/v1.6.1
c6f48771296bca0bd22724b208abafeae7d7b764        refs/tags/v1.6.0
EOF
        ;;
      *)
        # Do nothing.
        ;;
    esac
  }

  # Run this in a subshell to prevent exiting on failure.
  (
    source "${CLI}" -r 1.6.2 some-repo &> /dev/null
  )

  ASSERT_CMD_FAILED
  ASSERT_FILE_EQUALS "${actual_git_cmds_file}" "${expected_git_cmds_file}"
}

test_CreateGithubReleaseTest_CreateReleaseFailsWhenInvalidVersion() {
  cd "${TEST_CASE_TMPDIR}"
  # Run this in a subshell to prevent exiting on failure.
  (
    source "${CLI}" -r 1 some-repo &> /dev/null
  )
  ASSERT_CMD_FAILED
  (
    source "${CLI}" -r 1.2 some-repo &> /dev/null
  )
  ASSERT_CMD_FAILED
  (
    source "${CLI}" -r 1.2.a some-repo &> /dev/null
  )
  ASSERT_CMD_FAILED
  (
    source "${CLI}" -r a.b.c some-repo &> /dev/null
  )
  ASSERT_CMD_FAILED
  (
    source "${CLI}" -r 1.2.3.4 some-repo &> /dev/null
  )
  ASSERT_CMD_FAILED
  (
    source "${CLI}" -r invalid some-repo &> /dev/null
  )
  ASSERT_CMD_FAILED
}

test_CreateGithubReleaseTest_CreateReleaseFailsWhenNoRepoNameIsGiven() {
  cd "${TEST_CASE_TMPDIR}"
  # Run this in a subshell to prevent exiting on failure.
  (
    source "${CLI}" -r 1.6.0 &> /dev/null
  )
  ASSERT_CMD_FAILED
}

test_CreateGithubReleaseTest_CreateReleaseUsesCorrectGithubToken() {
  cd "${TEST_CASE_TMPDIR}"
  local -r access_token="a227da63673c236090a067c3f96b62e74dbd5857"
  local -r expected_url="https://ise-crypto:${access_token}@github.com/tink-crypto/some-repo"
  local -r expected_git_cmds_file="${TEST_CASE_TMPDIR}/expected_cmds.txt"
  cat << EOF > ${expected_git_cmds_file}
git ls-remote ${expected_url}
git clone ${expected_url}
git branch 1.6
git push origin 1.6
git checkout 1.6
git tag -a v1.6.0 -m some-repo version 1.6.0
git push origin v1.6.0
EOF
  local -r actual_git_cmds_file="${TEST_CASE_TMPDIR}/actual_git_cmds_file.txt"
  # Mock git command.
  git() {
    local -r command="$1"
    shift 1
    cmd_and_args="git ${command} $@"
    echo "${cmd_and_args}" >> "${actual_git_cmds_file}"
    case "${command}" in
      "ls-remote")
        cat << EOF
6c68b48c884e0aeb983b8864f35187d9584d0d74        HEAD
6c68b48c884e0aeb983b8864f35187d9584d0d74        refs/heads/main
EOF
        ;;
      "clone")
        local -r repo_name="${1##*/}"
        mkdir "${repo_name}"
        ;;
      *)
        # Do nothing
        ;;
    esac
  }

  # Run this in the caller's environment.
  (
    source "${CLI}" -r -t "${access_token}" 1.6.0 some-repo &> /dev/null
  )
  ASSERT_CMD_SUCCEEDED
  ASSERT_FILE_EQUALS "${actual_git_cmds_file}" "${expected_git_cmds_file}"
}

main() {
  run_all_tests "$@"
}

main "$@"
