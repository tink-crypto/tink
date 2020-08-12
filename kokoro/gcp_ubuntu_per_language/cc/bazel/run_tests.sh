#!/bin/bash

set -euo pipefail
cd ${KOKORO_ARTIFACTS_DIR}/git/tink

cd cc
use_bazel.sh $(cat .bazelversion)
bazel build ...
bazel test ...

# Run build and tests with the BoringSSL FIPS module
bazel clean
APPEND_AFTER='workspace(name = "tink_cc")'
NUM_MATCHES="$(grep -c "${APPEND_AFTER}" WORKSPACE)"
if (( $? != 0 || NUM_MATCHES != 1)); then
  echo "ERROR: Could not patch WORKSPACE to build BoringSSL with FIPS module"
  exit 1
fi

LOCAL_FIPS_REPOSITORY="local_repository(\n  name = \"boringssl\",\n  path = \"third_party\/boringssl_fips\/\",\n)"
sed -i '/'"${APPEND_AFTER}"'/a\\n'"${LOCAL_FIPS_REPOSITORY}" WORKSPACE

bazel build --define=use_only_fips=on
bazel test ... --define=use_only_fips=on --test_tag_filters=fips
