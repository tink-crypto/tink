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

# Deploys a Maven library.
#
# NOTE:
#   - This must be run from the root of the library workspace.

usage() {
  echo "Usage: $0 [-dh] [-n jars_name_prefix] [-u github_url] \\"
  echo "          <action (install|snapshot|release)> <library name> \\"
  echo "          <pom file> <version>"
  echo "  -d: Dry run. Only execute idempotent commands (default: false)."
  echo "  -h: Help. Print this usage information."
  echo "  -n: JARs name prefix. Prefix to apply to JAR names (default: "
  echo "      <library name>)."
  echo "  -u: GitHub URL. GitHub URL for Javadoc publishing; it is mandatory"
  echo "      when <action> is \"snaphot\" or \"release\"."
  exit 1
}

# Arguments to use for all git invocations.
readonly GIT_ARGS=(
  -c user.email=noreply@google.com
  -c user.name="Tink Team"
)

# Options.
DRY_RUN="false"
GIT_URL=
JAR_NAME_PREFIX=

# Positional arguments.
LIBRARY_NAME=
POM_FILE=
ARTIFACT_VERSION=

MAVEN_ARGS=()

parse_args() {
  # Parse options.
  while getopts "dhn::u::" opt; do
    case "${opt}" in
      d) DRY_RUN="true" ;;
      n) JAR_NAME_PREFIX="${OPTARG}" ;;
      u) GIT_URL="${OPTARG}" ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))

  readonly DRY_RUN
  readonly JAR_NAME_PREFIX
  readonly GIT_URL

  # Parse args.
  if (( $# < 4 )); then
    usage
  fi
  ACTION="$1"
  LIBRARY_NAME="$2"
  POM_FILE="$3"
  ARTIFACT_VERSION="$4"

  # Make sure the version has the correct format.
  if [[ ! "${ARTIFACT_VERSION}" =~ (^HEAD$|^[0-9]+\.[0-9]+\.[0-9]$) ]]; then
    usage
  fi

  case "${ACTION}" in
    install)
      MAVEN_ARGS+=( "install:install-file" )
      ARTIFACT_VERSION="${ARTIFACT_VERSION}-SNAPSHOT"
      ;;
    snapshot)
      if [[ -z "${GIT_URL}" ]]; then
        usage
      fi
      local -r maven_scripts_dir="$(cd "$(dirname "$0")" && pwd)"
      MAVEN_ARGS+=(
        "deploy:deploy-file"
        "-DrepositoryId=ossrh"
        "-Durl=https://oss.sonatype.org/content/repositories/snapshots"
        "--settings=${maven_scripts_dir}/settings.xml"
      )
      ARTIFACT_VERSION="${ARTIFACT_VERSION}-SNAPSHOT"
      ;;
    release)
      if [[ -z "${GIT_URL}" ]]; then
        usage
      fi
      MAVEN_ARGS+=(
        gpg:sign-and-deploy-file
        "${ARTIFACT_VERSION}"
        "-DrepositoryId=ossrh"
        "-Durl=https://oss.sonatype.org/service/local/staging/deploy/maven2/"
        "-X"
      )
      ;;
    *)
      usage
      ;;
  esac

  readonly ACTION
  readonly LIBRARY_NAME
  readonly POM_FILE
  readonly ARTIFACT_VERSION
  readonly MAVEN_ARGS
}

do_run_command() {
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
  do_run_command "$@"
  return $?
}

#######################################
# Runs a given command if DRY_RUN isn't true.
# Globals:
#   DRY_RUN
# Arguments:
#   The command to run and its arguments.
#######################################
do_run_if_not_dry_run() {
  print_command "$@"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "  *** Dry run, command not executed. ***"
    return 0
  fi
  do_run_command "$@"
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

#######################################
# Pusblishes Javadoc to GitHub pages.
#
# Globals:
#   ACTION
#   GIT_ARGS
#   GIT_URL
#   LIBRARY_NAME
#   ARTIFACT_VERSION
# Arguments:
#   workspace_dir: Workspace directory for the library.
#   javadoc: Javadoc library name.
#######################################
publish_javadoc_to_github_pages() {
  if [[ "${ACTION}" == "install" ]]; then
    echo "Local deployment, skipping publishing javadoc to GitHub Pages..."
    return 0
  fi

  local workspace_dir="$1"
  local javadoc="$2"

  local javadoc_file="$(echo_output_file "${workspace_dir}" "${javadoc}")"
  javadoc_file="${workspace_dir}/${javadoc_file}"
  readonly javadoc_file

  print_and_do rm -rf gh-pages
  print_and_do git "${GIT_ARGS[@]}" clone \
    --quiet --branch=gh-pages "${GIT_URL}" gh-pages > /dev/null
  (
    print_and_do cd gh-pages
    if [ -d "javadoc/${LIBRARY_NAME}/${ARTIFACT_VERSION}" ]; then
      print_and_do git "${GIT_ARGS[@]}" rm -rf \
          "javadoc/${LIBRARY_NAME}/${ARTIFACT_VERSION}"
    fi
    print_and_do mkdir -p "javadoc/${LIBRARY_NAME}/${ARTIFACT_VERSION}"
    print_and_do unzip "../${javadoc_file}" \
      -d "javadoc/${LIBRARY_NAME}/${ARTIFACT_VERSION}"
    print_and_do rm -rf "javadoc/${LIBRARY_NAME}/${ARTIFACT_VERSION}/META-INF/"
    print_and_do git "${GIT_ARGS[@]}" add \
      -f "javadoc/${LIBRARY_NAME}/${ARTIFACT_VERSION}"
    if [[ "$(git "${GIT_ARGS[@]}" status --porcelain)" ]]; then
      # Changes exist.
      do_run_if_not_dry_run \
        git "${GIT_ARGS[@]}" commit \
        -m "${LIBRARY_NAME}-${ARTIFACT_VERSION} Javadoc auto-pushed to gh-pages"

      do_run_if_not_dry_run \
        git "${GIT_ARGS[@]}" push -fq origin gh-pages > /dev/null
      echo -e "Published Javadoc to gh-pages.\n"
    else
      # No changes exist.
      echo -e "No changes in ${LIBRARY_NAME}-${ARTIFACT_VERSION} Javadoc.\n"
    fi
  )
}

main() {
  parse_args "$@"

  local -r jars_name_prefix="${JAR_NAME_PREFIX:-${LIBRARY_NAME}}"
  local -r library="${jars_name_prefix}.jar"
  local -r src_jar="${jars_name_prefix}-src.jar"
  local -r javadoc="${jars_name_prefix}-javadoc.jar"

  local -r workspace_dir="$(pwd)"

  print_and_do bazel build "${library}" "${src_jar}" "${javadoc}"

  local -r library_file="$(echo_output_file "." "${library}")"
  local -r src_jar_file="$(echo_output_file "." "${src_jar}")"
  local -r javadoc_file="$(echo_output_file "." "${javadoc}")"

  # Update the version in the POM file.
  do_run_if_not_dry_run sed -i \
    's/VERSION_PLACEHOLDER/'"${ARTIFACT_VERSION}"'/' "${POM_FILE}"

  do_run_if_not_dry_run mvn "${MAVEN_ARGS[@]}" \
    -Dfile="${library_file}" \
    -Dsources="${src_jar_file}" \
    -Djavadoc="${javadoc_file}" \
    -DpomFile="${POM_FILE}"

  # Add the placeholder back in the POM file.
  do_run_if_not_dry_run sed -i \
    's/'"${ARTIFACT_VERSION}"'/VERSION_PLACEHOLDER/' "${POM_FILE}"

  publish_javadoc_to_github_pages \
    "${workspace_dir}" \
    "${javadoc}"
}

main "$@"
