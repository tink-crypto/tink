#!/bin/bash

set -euo pipefail

cd "${KOKORO_ARTIFACTS_DIR}/git/tink/go"
go get github.com/google/tink/go/...
