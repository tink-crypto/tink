#!/bin/bash
# Copyright 2020 Google LLC
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


# This script creates the release artifacts of Tink Python which includes a
# source distribution and binary wheels for Linux and macOS.  All Python tests
# are exectued for each binary wheel and the source distribution.

set -euo pipefail

declare -a PYTHON_VERSIONS=
PYTHON_VERSIONS+=("3.7")
PYTHON_VERSIONS+=("3.8")
# TODO(ckl): Enable when macOS solution is in place.
#PYTHON_VERSIONS+=("3.9")
readonly PYTHON_VERSIONS

readonly PLATFORM="$(uname | tr '[:upper:]' '[:lower:]')"
readonly TINK_BASE="${PWD}/.."
readonly IMAGE_NAME="quay.io/pypa/manylinux2014_x86_64"
readonly IMAGE_DIGEST="sha256:d4604fe14cb0d691031f202ee7daf240e6d463297b060e2de60994d82a8f22ac"
readonly IMAGE="${IMAGE_NAME}@${IMAGE_DIGEST}"

build_linux() {
  echo "### Building Linux binary wheels ###"

  mkdir -p release

  # Use signatures for getting images from registry (see
  # https://docs.docker.com/engine/security/trust/content_trust/).
  export DOCKER_CONTENT_TRUST=1

  # Build binary wheels.
  docker run --volume "${TINK_BASE}:/tmp/tink" --workdir /tmp/tink/python \
    "${IMAGE}" /tmp/tink/python/tools/distribution/build_linux_binary_wheels.sh

  # Test binary wheels.
  docker run --volume "${TINK_BASE}:/tmp/tink" --workdir /tmp/tink/python \
    "${IMAGE}" /tmp/tink/python/tools/distribution/test_linux_binary_wheels.sh

  # Build source wheels.
  pip3 install wheel
  export TINK_PYTHON_SETUPTOOLS_OVERRIDE_BASE_PATH="${TINK_BASE}"
  # TODO(ckl): Is sudo necessary?
  sudo python3 setup.py sdist
  cp dist/*.tar.gz release/

  # Test install from source wheel
  pip3 list
  pip3 install release/*.tar.gz
  pip3 list
  find tink/ -not -path "*cc/pybind*" -type f -name "*_test.py" -print0 \
    | xargs -0 -n1 python3
}

build_macos() {
  echo "### Building macOS binary wheels ###"

  for v in "${PYTHON_VERSIONS[@]}"; do
    # Build binary wheel.
    local pip_command="pip${v}"
    ${pip_command} wheel .

    # Test binary wheel.
    # TODO(ckl): Implement test.
  done
}

main() {
  if [[ "${PLATFORM}" == 'linux' ]]; then
    build_linux
  elif [[ "${PLATFORM}" == 'darwin' ]]; then
    build_macos
  else
    echo "${PLATFORM} is not a supported platform."
    exit 1
  fi
}

main "$@"
