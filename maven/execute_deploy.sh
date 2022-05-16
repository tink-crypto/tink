#!/bin/bash

# Copyright 2018 Google LLC
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

# Fail on any error.
set -e

usage() {
  echo "Usage: $0 [-dlh] <maven goal> <version> <additional maven args...>"
  echo "  -d: Dry run. Only execute idempotent commands (default: FALSE)."
  echo "  -l: Local. Deploy locally (default: FALSE)."
  echo "  -h: Help. Print this usage information."
  exit 1
}

# Process flags.

DRY_RUN="false"
LOCAL="FALSE"

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

if (( $# < 2 )); then
  usage
fi

# Process arguments.

readonly MVN_GOAL="$1"
readonly VERSION="$2"
shift 2

# All remaining arguments are used as extra arguments to maven.
readonly EXTRA_MAVEN_ARGS=("$@")

# URL of the git repository used for javadoc publishing.
GIT_URL="git@github.com:google/tink.git"
if [ -n "${KOKORO_ROOT}" ]; then
  # GITHUB_ACCESS_TOKEN is populated from Keystore via the Kokoro configuration.
  GIT_URL="https://ise-crypto:${GITHUB_ACCESS_TOKEN}@github.com/google/tink.git"
fi
readonly GIT_URL

# Arguments to use for all git invocations.
declare -a GIT_ARGS=(-c user.email=noreply@google.com -c user.name="Tink Team")
readonly GIT_ARGS

do_command() {
  if ! "$@"; then
    echo "*** Failed executing command. ***"
    echo "Failed command: $@"
    exit 1
  fi
  return $?
}

print_command() {
  printf '%q ' '+' "$@"
  echo
}

print_and_do() {
  print_command "$@"
  do_command "$@"
  return $?
}

do_if_not_dry_run() {
  # $@ is an array containing a command to be executed and its arguments.
  print_command "$@"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "  *** Dry run, command not executed. ***"
    return 0
  fi
  do_command "$@"
  return $?
}

echo_output_file() {
  local workspace_dir="$1"
  local library="$2"

  (
    cd "${workspace_dir}"
    local file="bazel-bin/${library}"
    if [[ ! -e "${file}" ]]; then
       file="bazel-genfiles/${library}"
    fi
    if [[ ! -e "${file}" ]]; then
      echo "Could not find Bazel output file for ${library}"
      exit 1
    fi
    echo -n "${file}"
  )
}

deploy_library() {
  local library_name="$1"
  local workspace_dir="$2"
  local library="$3"
  local src_jar="$4"
  local javadoc="$5"
  local pom_file="$6"

  (
    print_and_do cd "${workspace_dir}"
    print_and_do bazel build "${library}" "${src_jar}" "${javadoc}"

    local library_file="$(echo_output_file "." "${library}")"
    local src_jar_file="$(echo_output_file "." "${src_jar}")"
    local javadoc_file="$(echo_output_file "." "${javadoc}")"

    # Update the version
    do_if_not_dry_run sed -i \
      's/VERSION_PLACEHOLDER/'"${VERSION}"'/' "${pom_file}"

    do_if_not_dry_run mvn "${MVN_GOAL}" \
      -Dfile="${library_file}" \
      -Dsources="${src_jar_file}" \
      -Djavadoc="${javadoc_file}" \
      -DpomFile="${pom_file}" \
      "${EXTRA_MAVEN_ARGS[@]:+${EXTRA_MAVEN_ARGS[@]}}"

    # Reverse the version change
    do_if_not_dry_run sed -i \
      's/'"${VERSION}"'/VERSION_PLACEHOLDER/' "${pom_file}"
  )

  publish_javadoc_to_github_pages \
    "${library_name}" \
    "${workspace_dir}" \
    "${javadoc}"
}

publish_javadoc_to_github_pages() {
  if [[ "${LOCAL}" == "true" ]]; then
    echo "Local deployment, skipping publishing javadoc to GitHub Pages..."
    return 0
  fi

  local library_name="$1"
  local workspace_dir="$2"
  local javadoc="$3"

  local javadoc_file="$(echo_output_file "${workspace_dir}" "${javadoc}")"
  javadoc_file="${workspace_dir}/${javadoc_file}"
  readonly javadoc_file

  print_and_do rm -rf gh-pages
  print_and_do git "${GIT_ARGS[@]}" clone \
    --quiet --branch=gh-pages "${GIT_URL}" gh-pages > /dev/null
  (
    print_and_do cd gh-pages
    if [ -d "javadoc/${library_name}/${VERSION}" ]; then
      print_and_do git "${GIT_ARGS[@]}" rm -rf \
          "javadoc/${library_name}/${VERSION}"
    fi
    print_and_do mkdir -p "javadoc/${library_name}/${VERSION}"
    print_and_do unzip "../${javadoc_file}" \
      -d "javadoc/${library_name}/${VERSION}"
    print_and_do rm -rf "javadoc/${library_name}/${VERSION}/META-INF/"
    print_and_do git "${GIT_ARGS[@]}" add \
      -f "javadoc/${library_name}/${VERSION}"
    if [[ "$(git "${GIT_ARGS[@]}" status --porcelain)" ]]; then
      # Changes exist.
      do_if_not_dry_run \
        git "${GIT_ARGS[@]}" commit \
        -m "${library_name}-${VERSION} Javadoc auto-pushed to gh-pages"

      do_if_not_dry_run \
        git "${GIT_ARGS[@]}" push -fq origin gh-pages > /dev/null
      echo -e "Published Javadoc to gh-pages.\n"
    else
      # No changes exist.
      echo -e "No changes in ${library_name}-${VERSION} Javadoc.\n"
    fi
  )
}

main() {
  deploy_library \
    tink \
    java_src \
    tink.jar \
    tink-src.jar \
    tink-javadoc.jar \
    "../$(dirname $0)/tink.pom.xml"

  deploy_library \
    tink-awskms \
    java_src \
    tink-awskms.jar \
    tink-awskms-src.jar \
    tink-awskms-javadoc.jar \
    "../$(dirname $0)/tink-awskms.pom.xml"

  deploy_library \
    tink-gcpkms \
    java_src \
    tink-gcpkms.jar \
    tink-gcpkms-src.jar \
    tink-gcpkms-javadoc.jar \
    "../$(dirname $0)/tink-gcpkms.pom.xml"

  deploy_library \
    tink-android \
    java_src \
    tink-android.jar \
    tink-android-src.jar \
    tink-android-javadoc.jar \
    "../$(dirname $0)/tink-android.pom.xml"

  deploy_library \
    apps-paymentmethodtoken \
    apps \
    paymentmethodtoken/maven.jar \
    paymentmethodtoken/maven-src.jar \
    paymentmethodtoken/maven-javadoc.jar \
    "../$(dirname $0)/apps-paymentmethodtoken.pom.xml"

  deploy_library \
    apps-rewardedads \
    apps \
    rewardedads/maven.jar \
    rewardedads/maven-src.jar \
    rewardedads/maven-javadoc.jar \
    "../$(dirname $0)/apps-rewardedads.pom.xml"

  deploy_library \
    apps-webpush \
    apps \
    webpush/maven.jar \
    webpush/maven-src.jar \
    webpush/maven-javadoc.jar \
    "../$(dirname $0)/apps-webpush.pom.xml"
}

main "$@"
