#!/bin/bash

# Copyright 2021 Google LLC
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

set -xe

install_cmake() {
  local cmake_version="3.21.3"
  local cmake_sha256="a19aa9fcf368e9d923cdb29189528f0fe00a0d08e752ba4e547af91817518696"

  local cmake_name="cmake-${cmake_version}-linux-x86_64"
  local cmake_archive="${cmake_name}.tar.gz"
  local cmake_url="https://github.com/Kitware/CMake/releases/download/v${cmake_version}/${cmake_archive}"

  local -r cmake_tmpdir="$(mktemp -dt tink-cmake.XXXXXX)"
  (
    cd "${cmake_tmpdir}"
    curl -OLS "${cmake_url}"
    echo "${cmake_sha256} ${cmake_archive}" | sha256sum -c

    tar xzf "${cmake_archive}"
  )
  export PATH="${cmake_tmpdir}/${cmake_name}/bin:${PATH}"
}

install_openssl() {
  local openssl_version="1.1.1l"
  local openssl_sha256="0b7a3e5e59c34827fe0c3a74b7ec8baef302b98fa80088d7f9153aa16fa76bd1"

  local openssl_name="openssl-${openssl_version}"
  local openssl_archive="${openssl_name}.tar.gz"
  local openssl_url="https://www.openssl.org/source/${openssl_archive}"

  local -r openssl_tmpdir="$(mktemp -dt tink-openssl.XXXXXX)"
  (
    cd "${openssl_tmpdir}"
    curl -OLS "${openssl_url}"
    echo "${openssl_sha256} ${openssl_archive}" | sha256sum -c

    tar xzf "${openssl_archive}"
    cd "${openssl_name}"
    ./config --prefix="${openssl_tmpdir}" --openssldir="${openssl_tmpdir}"
    make
    make install
  )
  export OPENSSL_ROOT_DIR="${openssl_tmpdir}"
  export PATH="${openssl_tmpdir}/bin:${PATH}"
}

main() {
  cd git*/tink

  ./kokoro/copy_credentials.sh
  if [[ -n "${KOKORO_ROOT}" ]]; then
    # TODO(b/201806781): Remove when no longer necessary.
    sudo apt-get install -y ca-certificates
    sudo rm -f /usr/share/ca-certificates/mozilla/DST_Root_CA_X3.crt
    sudo update-ca-certificates

    install_cmake
    install_openssl
  fi

  # Currently there is a limited list of targets that can be built with OpenSSL.
  # This list is expected to grow larger as new targets can use OpenSSL.
  TEST_TARGETS=(
    "tink_test_aead__internal_ssl_aead_test"
    "tink_test_aead__internal_ssl_aead_large_inputs_test"
    "tink_test_internal_aes_util_test"
    "tink_test_internal_err_util_test"
    "tink_test_internal_ec_util_test"
    "tink_test_internal_md_util_test"
    "tink_test_internal_rsa_util_test"
    "tink_test_subtle_aes_cmac_boringssl_test"
    "tink_test_subtle_aes_gcm_boringssl_test"
    "tink_test_subtle_aes_gcm_siv_boringssl_test"
    "tink_test_subtle_ecdsa_sign_boringssl_test"
    "tink_test_subtle_ed25519_sign_boringssl_test"
    "tink_test_subtle_ed25519_verify_boringssl_test"
    "tink_test_subtle_ecies_hkdf_recipient_kem_boringssl_test"
    "tink_test_subtle_hkdf_test"
    "tink_test_subtle_hmac_boringssl_test"
    "tink_test_subtle_random_test"
    "tink_test_subtle_rsa_ssa_pss_sign_boringssl_test"
    "tink_test_subtle_rsa_ssa_pss_verify_boringssl_test"
    "tink_test_subtle_rsa_ssa_pkcs1_sign_boringssl_test"
    "tink_test_subtle_rsa_ssa_pkcs1_verify_boringssl_test"
    "tink_test_subtle_xchacha20_poly1305_boringssl_test"
  )

  echo "========================================================= Running cmake"
  cmake --version
  cmake . \
    -DTINK_BUILD_TESTS=ON \
    -DCMAKE_CXX_STANDARD=11 \
    -DTINK_USE_SYSTEM_OPENSSL=ON
  echo "==================================================== Building with make"
  make -j "$(nproc)" "${TEST_TARGETS[@]}"
  echo "======================================================= Testing targets"
  # Execute all tests that were built using the above make invocation.
  ctest -E ".*_NOT_BUILT"
  echo "================================================== Done testing targets"
}

main "$@"
