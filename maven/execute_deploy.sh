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
  echo "Usage: $0 [-dh] <action (install|snapshot|release)> <version>"
  echo "  -d: Dry run. Only execute idempotent commands (default: false)."
  echo "  -h: Help. Print this usage information."
  exit 1
}

DRY_RUN="false"

process_args() {
  # Process options.
  while getopts "dh" opt; do
    case "${opt}" in
      d) DRY_RUN="true" ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))
  readonly DRY_RUN

  if (( $# < 2 )); then
    usage
  fi

  # Process arguments.
  readonly ACTION="$1"
  readonly VERSION="$2"
}

main() {
  process_args "$@"

  # URL of the git repository used for javadoc publishing.
  local git_user="git"
  if [ -n "${KOKORO_ROOT}" ]; then
    # GITHUB_ACCESS_TOKEN is populated by Kokoro.
    git_user="ise-crypto:${GITHUB_ACCESS_TOKEN}"
  fi
  readonly git_user
  local -r git_url="${git_user}@github.com:google/tink.git"

  local -r maven_scripts_dir="$(cd "$(dirname "$0")" && pwd)"
  local -r tink_root="$(cd ${maven_scripts_dir}/.. && pwd)"
  local common_maven_deploy_library_options=()
  if [[ "${DRY_RUN}" == "true" ]]; then
    common_maven_deploy_library_options+=( -d )
  fi
  common_maven_deploy_library_options+=( -u "${git_url}" )
  readonly common_maven_deploy_library_options
  (
    cd "${tink_root}/java_src"

    "${maven_scripts_dir}/maven_deploy_library.sh" \
      "${common_maven_deploy_library_options[@]}" "${ACTION}" tink \
      "${maven_scripts_dir}/tink.pom.xml" "${VERSION}"

     "${maven_scripts_dir}/maven_deploy_library.sh" \
      "${common_maven_deploy_library_options[@]}" "${ACTION}" tink-awskms \
      "${maven_scripts_dir}/tink-awskms.pom.xml" "${VERSION}"

     "${maven_scripts_dir}/maven_deploy_library.sh" \
      "${common_maven_deploy_library_options[@]}" "${ACTION}" tink-gcpkms \
      "${maven_scripts_dir}/tink-gcpkms.pom.xml" "${VERSION}"

     "${maven_scripts_dir}/maven_deploy_library.sh" \
      "${common_maven_deploy_library_options[@]}" "${ACTION}" tink-android \
      "${maven_scripts_dir}/tink-android.pom.xml" "${VERSION}"
  )

  (
    cd "${tink_root}/apps"

    "${maven_scripts_dir}/maven_deploy_library.sh" \
      "${common_maven_deploy_library_options[@]}" \
      -n paymentmethodtoken/maven "${ACTION}" apps-paymentmethodtoken \
      "${maven_scripts_dir}/apps-paymentmethodtoken.pom.xml" "${VERSION}"

    "${maven_scripts_dir}/maven_deploy_library.sh" \
      "${common_maven_deploy_library_options[@]}" \
      -n rewardedads/maven "${ACTION}" apps-rewardedads \
      "${maven_scripts_dir}/apps-rewardedads.pom.xml" "${VERSION}"

    "${maven_scripts_dir}/maven_deploy_library.sh" \
      "${common_maven_deploy_library_options[@]}" -n webpush/maven \
      "${ACTION}" apps-webpush "${maven_scripts_dir}/apps-webpush.pom.xml" \
      "${VERSION}"
  )
}

main "$@"
