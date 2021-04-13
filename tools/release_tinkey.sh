#!/bin/bash
# This script creates a Tinkey distribution and uploads it to Google Cloud
# Storage.
# Prerequisites:
#   - Google Cloud SDK: https://cloud.google.com/sdk/install
#   - Write access to the "tinkey" GCS bucket. Ping tink-dev@.
#   - bazel: https://bazel.build/

usage() {
  echo "Usage: $0 [-dh] <version>"
  echo "  -d: Dry run. Only execute idempotent commands (default: FALSE)."
  echo "  -h: Help. Print this usage information."
  exit 1
}

# Process flags.

DRY_RUN="false"

while getopts "dh" opt; do
  case "${opt}" in
    d) DRY_RUN="true" ;;
    h) usage ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

readonly DRY_RUN

# Process script arguments.

VERSION="$1"
shift 1

if [ -z "${VERSION}" ]; then
  VERSION="snapshot"
fi

if [[ "${VERSION}" =~ " " ]]; then
  echo "Version name must not have any spaces"
  exit 3
fi

# Set up parameters.

readonly GCS_LOCATION="gs://tinkey/"

readonly TMP_DIR="$(mktemp -dt tinkey.XXXXXX)"

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

build_tinkey() {
  print_and_do cd tools

  print_and_do bazel build tinkey:tinkey_deploy.jar

  print_and_do cp bazel-bin/tinkey/tinkey_deploy.jar "${TMP_DIR}"

  print_and_do cd "${TMP_DIR}"

  cat <<EOF > tinkey
#!/usr/bin/env sh

java -jar "\$(dirname \$0)/tinkey_deploy.jar" "\$@"
EOF

  cat <<EOF > tinkey.bat
java -jar "%~dp0\tinkey_deploy.jar" %*
EOF

  chmod 755 tinkey

  print_and_do tar -czvpf "tinkey-${VERSION}.tar.gz" tinkey_deploy.jar tinkey tinkey.bat
}

upload_to_gcs() {
  print_and_do cd "${TMP_DIR}"

  shasum -a 256 "tinkey-${VERSION}.tar.gz"

  do_if_not_dry_run gsutil cp "tinkey-${VERSION}.tar.gz" "${GCS_LOCATION}"
}

main() {
  build_tinkey
  upload_to_gcs
}

main "$@"
