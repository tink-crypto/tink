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


# This script builds BoringSSL as described in the security policy
# https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3678.pdf

set -e

if [[ "$(uname)" != "Linux" ]]; then
    echo "ERROR: BoringSSL only supports FIPS mode in Linux."
    exit 1
fi

# Install required build tools
#
# Clang 7.0.1
CLANG_PLATFORM="x86_64-linux-gnu-ubuntu-16.04"
CLANG_SHA256SUM=02ad925add5b2b934d64c3dd5cbd1b2002258059f7d962993ba7f16524c3089c
curl -OLsS https://releases.llvm.org/7.0.1/clang+llvm-7.0.1-"${CLANG_PLATFORM}".tar.xz
echo "${CLANG_SHA256SUM}" clang+llvm-7.0.1-"${CLANG_PLATFORM}".tar.xz | sha256sum --check

tar -xf clang+llvm-7.0.1-"${CLANG_PLATFORM}".tar.xz
rm clang+llvm-7.0.1-"${CLANG_PLATFORM}".tar.xz

export HOME="${PWD}"
printf "set(CMAKE_C_COMPILER \"clang\")\nset(CMAKE_CXX_COMPILER \"clang++\")\n" > "${HOME}/toolchain"
export PATH="${PWD}/clang+llvm-7.0.1-${CLANG_PLATFORM}/bin:${PATH}"


# Go 1.12.7
GO_PLATFORM="linux-amd64"
GO_SHA256SUM="66d83bfb5a9ede000e33c6579a91a29e6b101829ad41fffb5c5bb6c900e109d9"
curl -OLsS https://dl.google.com/go/go1.12.7."${GO_PLATFORM}".tar.gz
echo "${GO_SHA256SUM}" go1.12.7."${GO_PLATFORM}".tar.gz | sha256sum --check
tar -xf go1.12.7."${GO_PLATFORM}".tar.gz
rm go1.12.7."${GO_PLATFORM}".tar.gz

export PATH="${PWD}/go/bin:${PATH}"

# Ninja 1.9.0
NINJA_SHA256SUM="1b1235f2b0b4df55ac6d80bbe681ea3639c9d2c505c7ff2159a3daf63d196305"
curl -OLsS https://github.com/ninja-build/ninja/releases/download/v1.9.0/ninja-linux.zip
echo "${NINJA_SHA256SUM}" ninja-linux.zip | sha256sum --check

unzip ninja-linux.zip
rm ninja-linux.zip

export PATH="${PWD}:${PATH}"



# Download BoringSSL and verify
BORINGSSL_SHA256SUM="3b5fdf23274d4179c2077b5e8fa625d9debd7a390aac1d165b7e47234f648bb8"

# Download archive and verify checksum
curl -OLsS https://commondatastorage.googleapis.com/chromium-boringssl-fips/boringssl-ae223d6138807a13006342edfeef32e813246b39.tar.xz
echo "${BORINGSSL_SHA256SUM}" boringssl-ae223d6138807a13006342edfeef32e813246b39.tar.xz | sha256sum --check

tar -xf boringssl-ae223d6138807a13006342edfeef32e813246b39.tar.xz
rm boringssl-ae223d6138807a13006342edfeef32e813246b39.tar.xz

# Build BoringSSL
(
  cd boringssl
  mkdir build && cd build && cmake -GNinja -DCMAKE_TOOLCHAIN_FILE=${HOME}/toolchain -DFIPS=1 -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=1 ..
  ninja
  ninja run_tests

  if [[ "$(tool/bssl isfips)" != "1"  ]]; then
      echo "ERROR: BoringSSL FIPS build check failed."
      exit 1
  fi
)

# Cleanup build tools
rm -rf clang+llvm-7.0.1-"${CLANG_PLATFORM}"
rm -rf go
rm ninja
rm toolchain
