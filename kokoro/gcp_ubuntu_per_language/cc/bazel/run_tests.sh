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

mapfile LOCAL_FIPS_REPOSITORY <<EOM
local_repository(
  name = "boringssl",
  path = "third_party/boringssl_fips",
)
EOM

printf -v INSERT_TEXT '\\n%s' "${LOCAL_FIPS_REPOSITORY[@]//$'\n'/}"
sed -i.bak "/${APPEND_AFTER}/a \\${INSERT_TEXT}" WORKSPACE

bazel build --//third_party/tink/cc/config:use_only_fips=True -- ...
bazel test --//third_party/tink/cc/config:use_only_fips=True --test_tag_filters=fips -- ...

mv WORKSPACE.bak WORKSPACE
