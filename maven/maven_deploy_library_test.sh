#!/bin/bash
# Copyright 2023 Google LLC
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

readonly CLI_RELATIVE_PATH="${1:-"maven_deploy_library.sh"}"
readonly CLI="${DEFAULT_DIR}/${CLI_RELATIVE_PATH}"
readonly TEST_UTILS="${DEFAULT_DIR}/${2}"
readonly SETTINGS_XML="${DEFAULT_DIR}/${3}"

readonly RELATIVE_MVN_DIR_PATH="$(dirname "${CLI_RELATIVE_PATH}")"

readonly ACTUAL_MVN_CMD="$(which mvn)"

# Load the test library.
source "${TEST_UTILS}"

create_maven_folder_and_pom_file() {
  mkdir -p "${RELATIVE_MVN_DIR_PATH}"
  cp "${SETTINGS_XML}" "${RELATIVE_MVN_DIR_PATH}"
  cat << EOF > "${RELATIVE_MVN_DIR_PATH}/tink.pom.xml"
<project xmlns="http://maven.apache.org/POM/4.0.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <name>Tink Cryptography API</name>
  <description>Tink is a small cryptographic library that provides a safe, simple, agile and fast way to accomplish some common cryptographic tasks.</description>

  <parent>
    <groupId>org.sonatype.oss</groupId>
    <artifactId>oss-parent</artifactId>
    <version>7</version>
  </parent>

  <groupId>com.google.crypto.tink</groupId>
  <artifactId>tink</artifactId>
  <version>VERSION_PLACEHOLDER</version>

  <!-- Skip the rest as not useful here -->
</project>
EOF
}

# Mock Bazel command that pretends to build a given target.
mock_bazel() {
  local -r bazel_cmd="$1"
  case "${bazel_cmd}" in
    "build")
      mkdir bazel-bin/
      touch bazel-bin/tink.jar
      touch bazel-bin/tink-src.jar
      # Create the javadoc zip.
      mkdir META-INF
      touch META-INF/MANIFEST.MF
      zip bazel-bin/tink-javadoc.jar META-INF/
      ;;
    *) return 1 ;; # No other command should be called.
  esac
}

test_MavenDeployLibraryTest_InstallSucceeds() {
  cd "${TEST_CASE_TMPDIR}"
  create_maven_folder_and_pom_file

  cat << EOF > expected_commands.txt
bazel build tink.jar tink-src.jar tink-javadoc.jar
mvn install:install-file -Dfile=${TEST_CASE_TMPDIR}/bazel-bin/tink.jar \
-Dsources=${TEST_CASE_TMPDIR}/bazel-bin/tink-src.jar \
-Djavadoc=${TEST_CASE_TMPDIR}/bazel-bin/tink-javadoc.jar \
-DpomFile=${RELATIVE_MVN_DIR_PATH}/tink.pom.xml
EOF

  bazel() {
    echo "bazel $@" >> actual_commands.txt
    mock_bazel "$@"
  }

  bazelisk() {
    bazel "$@"
  }

  mvn() {
    echo "mvn $@" >> actual_commands.txt
  }

  (
    source "${CLI}" install tink "${RELATIVE_MVN_DIR_PATH}/tink.pom.xml" HEAD \
      > /dev/null
  )
  ASSERT_CMD_SUCCEEDED
  ASSERT_FILE_EQUALS actual_commands.txt expected_commands.txt
}

test_MavenDeployLibraryTest_ReleaseFailsIfNoUrl() {
  cd "${TEST_CASE_TMPDIR}"
  create_maven_folder_and_pom_file
  # No calls to bazel should be made.
  bazel() {
    return 1
  }
  bazelisk() {
    bazel "$@"
  }
  # No calls to mvn should be made.
  mvn() {
    return 1
  }
  (
    source "${CLI}" release tink "${RELATIVE_MVN_DIR_PATH}/tink.pom.xml" 1.2.3 \
      > /dev/null
  )
  ASSERT_CMD_FAILED
}


create_test_gpg_key() {
  gpg --pinentry-mode loopback --gen-key --batch << EOF
Key-Type: 1
Key-Length: 2048
Subkey-Type: 1
Subkey-Length: 2048
Name-Real: Test User
Name-Email: test@test.com
Expire-Date: 0
Passphrase: This-is-a-passphrase
EOF
}

delete_gpg_test_key() {
  gpg --list-secret-keys --with-colon --fingerprint test@test.com\
    | grep -m 1 fpr \
    | sed -n 's/^fpr:::::::::\([[:alnum:]]\+\):/\1/p' \
    | xargs gpg --delete-secret-keys --batch --yes
}

test_MavenDeployLibraryTest_ReleaseSucceeds() {
  cd "${TEST_CASE_TMPDIR}"
  create_maven_folder_and_pom_file

  cat << EOF > expected_commands.txt
bazel build tink.jar tink-src.jar tink-javadoc.jar
mvn gpg:sign-and-deploy-file -DrepositoryId=ossrh \
-Durl=https://oss.sonatype.org/service/local/staging/deploy/maven2/ \
-Dgpg.keyname=tink-dev@google.com \
--settings=${TEST_CASE_TMPDIR}/${RELATIVE_MVN_DIR_PATH}/settings.xml \
-X -Dfile=${TEST_CASE_TMPDIR}/bazel-bin/tink.jar \
-Dsources=${TEST_CASE_TMPDIR}/bazel-bin/tink-src.jar \
-Djavadoc=${TEST_CASE_TMPDIR}/bazel-bin/tink-javadoc.jar \
-DpomFile=${RELATIVE_MVN_DIR_PATH}/tink.pom.xml
EOF

  bazel() {
    echo "bazel $@" >> actual_commands.txt
    mock_bazel "$@"
  }

  bazelisk() {
    bazel "$@"
  }

  git() {
    mkdir -p gh-pages
  }

  mvn() {
    echo "mvn $@" >> actual_commands.txt
    local -r repo_url="https://oss.sonatype.org/service/local/staging/deploy/maven2/"
    # Make sure the correct URL is set, if not, return. This is to guarantee the
    # parameter is replaced with the local URI below.
    if ! echo "$@" | grep "${repo_url}" > /dev/null; then
      echo "URL not found" >&2
      return 1
    fi
    params=($(echo "$@" | sed 's#'${repo_url}'#file://'${TEST_CASE_TMPDIR}'#g' \
      | sed 's#tink-dev@google.com#test@test.com#g'))

    export SONATYPE_USERNAME="some_username"
    export SONATYPE_PASSWORD="some_password"
    export TINK_DEV_MAVEN_PGP_PASSPHRASE="This-is-a-passphrase"

    create_test_gpg_key || return 1
    "${ACTUAL_MVN_CMD}" "${params[@]}" || return 1
    delete_gpg_test_key || return 1
  }

  (
    source "${CLI}" -u github.com/tink-crypto/tink-java release tink \
      "${RELATIVE_MVN_DIR_PATH}/tink.pom.xml" 1.2.3 > /dev/null
  )
  ASSERT_CMD_SUCCEEDED
  ASSERT_FILE_EQUALS actual_commands.txt expected_commands.txt
}

test_MavenDeployLibraryTest_SnapshotSucceeds() {
  cd "${TEST_CASE_TMPDIR}"
  create_maven_folder_and_pom_file

  cat << EOF > expected_commands.txt
bazel build tink.jar tink-src.jar tink-javadoc.jar
mvn deploy:deploy-file -DrepositoryId=ossrh \
-Durl=https://oss.sonatype.org/content/repositories/snapshots \
--settings=${TEST_CASE_TMPDIR}/${RELATIVE_MVN_DIR_PATH}/settings.xml \
-Dfile=${TEST_CASE_TMPDIR}/bazel-bin/tink.jar \
-Dsources=${TEST_CASE_TMPDIR}/bazel-bin/tink-src.jar \
-Djavadoc=${TEST_CASE_TMPDIR}/bazel-bin/tink-javadoc.jar \
-DpomFile=${RELATIVE_MVN_DIR_PATH}/tink.pom.xml
EOF

  bazel() {
    echo "bazel $@" >> actual_commands.txt
    mock_bazel "$@"
  }

  bazelisk() {
    bazel "$@"
  }

  git() {
    mkdir -p gh-pages
  }

  mvn() {
    echo "mvn $@" >> actual_commands.txt
  }

  (
    source "${CLI}" -u github.com/tink-crypto/tink-java snapshot tink \
      "${RELATIVE_MVN_DIR_PATH}/tink.pom.xml" HEAD > /dev/null
  )
  ASSERT_CMD_SUCCEEDED
  ASSERT_FILE_EQUALS actual_commands.txt expected_commands.txt
}

main() {
  run_all_tests "$@"
}

main "$@"
