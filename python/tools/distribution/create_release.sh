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

set -euox pipefail

declare -a PYTHON_VERSIONS=
PYTHON_VERSIONS+=("3.7")
PYTHON_VERSIONS+=("3.8")
PYTHON_VERSIONS+=("3.9")
PYTHON_VERSIONS+=("3.10")
readonly PYTHON_VERSIONS

readonly PLATFORM="$(uname | tr '[:upper:]' '[:lower:]')"

export TINK_PYTHON_ROOT_PATH="${PWD}"
readonly TINK_VERSION="$(grep ^TINK "${TINK_PYTHON_ROOT_PATH}/VERSION" \
  | awk '{gsub(/"/, "", $3); print $3}')"

readonly IMAGE_NAME="quay.io/pypa/manylinux2014_x86_64"
readonly IMAGE_DIGEST="sha256:31d7d1cbbb8ea93ac64c3113bceaa0e9e13d65198229a25eee16dc70e8bf9cf7"
readonly IMAGE="${IMAGE_NAME}@${IMAGE_DIGEST}"

#######################################
# Builds Tink Python built distribution (Wheel) [1].
#
# This function must be called from within the Tink Python's root folder.
#
# [1] https://packaging.python.org/en/latest/glossary/#term-Built-Distribution
# Globals:
#   None
# Arguments:
#   None
#######################################
__create_and_test_wheels_for_linux() {
  echo "### Building and testing Linux binary wheels ###"
  # Use signatures for getting images from registry (see
  # https://docs.docker.com/engine/security/trust/content_trust/).
  export DOCKER_CONTENT_TRUST=1

  # We use setup.py to build wheels; setup.py makes changes to the WORKSPACE
  # file so we save a copy for backup.
  cp WORKSPACE WORKSPACE.bak

  local -r tink_base_dir="/tmp/tink"
  local -r tink_py_relative_path="${PWD##*/}"
  local -r workdir="${tink_base_dir}/${tink_py_relative_path}"
  # Build binary wheels.
  docker run \
    --volume "${TINK_PYTHON_ROOT_PATH}/..:${tink_base_dir}" \
    --workdir "${workdir}" \
    -e TINK_PYTHON_SETUPTOOLS_OVERRIDE_BASE_PATH="${tink_base_dir}" \
    "${IMAGE}" \
    "${workdir}/tools/distribution/build_linux_binary_wheels.sh"

  ## Test binary wheels.
  docker run \
    --volume "${TINK_PYTHON_ROOT_PATH}/..:${tink_base_dir}" \
    --workdir "${workdir}" \
    "${IMAGE}" \
    "${workdir}/tools/distribution/test_linux_binary_wheels.sh"

  # Docker runs as root so we transfer ownership to the non-root user.
  sudo chown -R "$(id -un):$(id -gn)" "${TINK_PYTHON_ROOT_PATH}"
  # Restore the original WORKSPACE.
  mv WORKSPACE.bak WORKSPACE
}

#######################################
# Builds Tink Python source distribution [1].
#
# This function must be called from within the Tink Python's root folder.
#
# [1] https://packaging.python.org/en/latest/glossary/#term-Source-Distribution-or-sdist
# Globals:
#   PYTHON_VERSIONS
# Arguments:
#   None
#######################################
__create_and_test_sdist_for_linux() {
  echo "### Building and testing Linux source distribution ###"
  local sorted=( $( echo "${PYTHON_VERSIONS[@]}" \
    | xargs -n1 | sort -V | xargs ) )
  local latest="${sorted[${#sorted[@]}-1]}"
  enable_py_version "${latest}"

  # Patch the workspace to use http_archive rules which specify the release tag.
  #
  # This is done so that an already patched version of WORKSPACE is present in
  # the sdist. Then, when building from the sdist, the default patching logic
  # in performed by setup.py will be a no-op.
  #
  # TODO(b/281635529): Use a container for a more hermetic testing environment.
  cp WORKSPACE WORKSPACE.bak

  # Build source distribution.
  TINK_PYTHON_SETUPTOOLS_TAGGED_VERSION="${TINK_VERSION}" \
    python3 setup.py sdist --owner=root --group=root
  local sdist_filename="tink-${TINK_VERSION}.tar.gz"
  cp "dist/${sdist_filename}" release/

  # Restore the original WORKSPACE.
  mv WORKSPACE.bak WORKSPACE

  # Test install from source distribution.
  python3 --version
  python3 -m pip list
  # Install Tink dependencies.
  python3 -m pip install --require-hashes --no-deps -r requirements_all.txt
  python3 -m pip install --no-deps --no-index -v \
    "release/${sdist_filename}[all]"
  python3 -m pip list
  find tink/ -not -path "*cc/pybind*" -type f -name "*_test.py" -print0 \
    | xargs -0 -n1 python3
}

#######################################
# Creates a Tink Python distribution for Linux.
#
# This function must be called from within the Tink Python's root folder.
#
# Globals:
#   None
# Arguments:
#   None
#######################################
create_distribution_for_linux() {
  __create_and_test_wheels_for_linux
  __create_and_test_sdist_for_linux
}

#######################################
# Creates a Tink Python distribution for MacOS.
#
# This function must be called from within the Tink Python's root folder.
#
# Globals:
#   PYTHON_VERSIONS
# Arguments:
#   None
#######################################
create_distribution_for_macos() {
  echo "### Building macOS binary wheels ###"

  for v in "${PYTHON_VERSIONS[@]}"; do
    enable_py_version "${v}"

    # Build binary wheel.
    python3 -m pip wheel -w release .

    # Test binary wheel.
    # TODO(ckl): Implement test.
  done
}

enable_py_version() {
  # A partial version number (e.g. "3.9").
  local partial_version="$1"

  # The latest installed Python version that matches the partial version number
  # (e.g. "3.9.5").
  local version="$(pyenv versions --bare | grep "${partial_version}" | tail -1)"

  # Set current Python version via environment variable.
  pyenv shell "${version}"

  # Update environment.
  python3 -m pip install --require-hashes -r \
    "${TINK_PYTHON_ROOT_PATH}/tools/distribution/requirements.txt"
}

main() {
  eval "$(pyenv init -)"
  mkdir -p release

  if [[ "${PLATFORM}" == 'linux' ]]; then
    create_distribution_for_linux
  elif [[ "${PLATFORM}" == 'darwin' ]]; then
    create_distribution_for_macos
  else
    echo "${PLATFORM} is not a supported platform."
    exit 1
  fi
}

main "$@"
