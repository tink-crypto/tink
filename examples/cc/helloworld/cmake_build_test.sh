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

#!/bin/bash

set -e

readonly TINK_USE_CXX_STANDARD=11

# Test for using Tink in a CMake project.

if [[ -z "${TEST_TMPDIR}" ]]; then
  echo "Error: TEST_TMPDIR must be set to a temporary working directory."
  exit 1
fi

if [[ -z "${TEST_SRCDIR}" ]]; then
  echo "Error: TEST_SRCDIR must be set to Tink's parent directory."
  exit 1
fi

# XDG_CACHE_HOME must be set for a successful build of BoringSSL.
export XDG_CACHE_HOME="${TEST_TMPDIR}/cache"
TEST_DATA_DIR="${TEST_SRCDIR}/tink/examples/cc/helloworld"
CMAKE_LISTS_FILE="${TEST_DATA_DIR}/CMakeLists_for_CMakeBuildTest.txt"
HELLO_WORLD_SRC="${TEST_DATA_DIR}/hello_world.cc"
KEYSET_FILE="${TEST_DATA_DIR}/aes128_gcm_test_keyset_json.txt"

PROJECT_DIR="${TEST_TMPDIR}/my_project"
PLAINTEXT_FILE="${TEST_TMPDIR}/example_plaintext.txt"
CIPHERTEXT_FILE="${TEST_TMPDIR}/ciphertext.bin"
DECRYPTED_FILE="${TEST_TMPDIR}/decrypted.txt"
AAD_TEXT="some associated data"

# If "true" build and install OpenSSL and build Tink against it.
USE_OPENSSL="false"
# If "true" build and install Abseil and build Tink against it.
USE_INSTALLED_ABSEIL="false"

# Parse parameters.
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --openssl)
      USE_OPENSSL="true"
      shift
      ;;
    # Use prebuilt static libraries of Abseil.
    --use_installed_abseil)
      USE_INSTALLED_ABSEIL="true"
      shift
      ;;
    *)
      echo "Unknown parameter - $1"
      exit 1
  esac
done

#######################################
# Install a given version of OpenSSL in a temporary directory
#
# Adds the directory to PATH and sets OPENSSL_ROOT_DIR accordingly.
#
# Globals:
#   OPENSSL_ROOT_DIR Gets populated with OpenSSL temporary directory.
#   PATH Gets updated with bin's path.
# Arguments:
#   openssl_version Version of OpenSSL to install, e.g., 1.1.1l.
#######################################
install_openssl() {
  local openssl_version="$1"

  local openssl_name="openssl-${openssl_version}"
  local openssl_archive="${openssl_name}.tar.gz"
  local openssl_url="https://www.openssl.org/source/${openssl_archive}"
  local openssl_sha256="$(curl -sS https://www.openssl.org/source/${openssl_archive}.sha256)"

  local -r openssl_tmpdir="$(mktemp -dt tink-openssl.XXXXXX)"
  (
    cd "${openssl_tmpdir}"
    curl -OLsS "${openssl_url}"
    echo "${openssl_sha256} ${openssl_archive}" | sha256sum -c

    tar xzf "${openssl_archive}"
    cd "${openssl_name}"
    ./config --prefix="${openssl_tmpdir}" --openssldir="${openssl_tmpdir}"
    make -j"$(nproc)"
    make install
  )
  export OPENSSL_ROOT_DIR="${openssl_tmpdir}"
  export PATH="${openssl_tmpdir}/bin:${PATH}"
}

#######################################
# Install Abeseil into a temporary folder.
#
# Globals:
#   ABSEIL_INSTALL_PATH Gets populated with Abseil's installation path.
# Arguments:
#   abseil_commit Abseils commit to lookup.
#######################################
install_abseil() {
  local -r abseil_commit="$1"
  local -r abseil_tmpdir="$(mktemp -dt tink-abseil.XXXXXX)"
  local -r abseil_install_dir="${abseil_tmpdir}/install"
  (
    cd "${abseil_tmpdir}"
    mkdir "install"
    curl -OLsS "https://github.com/abseil/abseil-cpp/archive/${abseil_commit}.zip"
    unzip "${abseil_commit}.zip" && cd "abseil-cpp-${abseil_commit}"
    mkdir build && cd build
    cmake .. \
      -DCMAKE_INSTALL_PREFIX="${abseil_install_dir}" \
      -DCMAKE_CXX_STANDARD="${TINK_USE_CXX_STANDARD}"
    cmake --build . --target install
  )
  export ABSEIL_INSTALL_PATH="${abseil_install_dir}"
}


#######################################
# Builds the hello world project
#
# Globals:
#   USE_OPENSSL if "true" install OpenSSL and build against it.
#   USE_INSTALLED_ABSEIL if "true" install Abseil and build against it.
# Arguments:
#   None
#######################################
build_hello_world() {
  local cmake_parameters=(
    -DCMAKE_CXX_STANDARD="${TINK_USE_CXX_STANDARD}"
  )
  if [[ "${USE_OPENSSL}" == "true" ]]; then
    # Install OpenSSL in a temporary directory.
    install_openssl "1.1.1l"
    cmake_parameters+=( -DTINK_USE_SYSTEM_OPENSSL=ON )
  fi
  if [[ "${USE_INSTALLED_ABSEIL}" == "true" ]]; then
    # Commit from 2021-12-03
    install_abseil "9336be04a242237cd41a525bedfcf3be1bb55377"
    cmake_parameters+=( -DCMAKE_PREFIX_PATH="${ABSEIL_INSTALL_PATH}" )
    cmake_parameters+=( -DTINK_USE_INSTALLED_ABSEIL=ON )
  fi
  readonly cmake_parameters
  (
    mkdir build && cd build
    cmake --version
    cmake .. "${cmake_parameters[@]}"
    make -j"$(nproc)"
  )
}

main() {
  # Create necessary directories, and create a symlink to Tink in the
  # "my_project" directory.
  mkdir -p "${XDG_CACHE_HOME}"
  mkdir -p "${PROJECT_DIR}" "${PROJECT_DIR}/third_party"
  ln -s "${TEST_SRCDIR}/tink" "${PROJECT_DIR}/third_party/tink"

  # Copy "my_project" files.
  cp "${HELLO_WORLD_SRC}" "${KEYSET_FILE}" "${PROJECT_DIR}"
  cp "${CMAKE_LISTS_FILE}" "${PROJECT_DIR}/CMakeLists.txt"

  # Move into the newly populated project directory.
  cd "${PROJECT_DIR}"

  # Build the project. This will produce ./build/hello_world.
  build_hello_world

  # Create a plaintext.
  echo "This is some message to be encrypted." > "${PLAINTEXT_FILE}"

  # Run encryption & decryption.
  ./build/hello_world \
    "${KEYSET_FILE}" \
    encrypt \
    "${PLAINTEXT_FILE}" \
    "${AAD_TEXT}" \
    "${CIPHERTEXT_FILE}"

  ./build/hello_world \
    "${KEYSET_FILE}" \
    decrypt \
    "${CIPHERTEXT_FILE}" \
    "${AAD_TEXT}" \
    "${DECRYPTED_FILE}"

  # Check that decryption is correct.
  diff -q "${DECRYPTED_FILE}" "${PLAINTEXT_FILE}"
  if [ $? -ne 0 ]; then
    echo "--- Failure: the decrypted file differs from the original plaintext."
    diff "${DECRYPTED_FILE}" "${PLAINTEXT_FILE}"
    exit 1
  fi
  echo "+++ Success: decryption was correct."
}

main
