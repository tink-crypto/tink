// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////
#include "tink/aead/internal/aead_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "openssl/evp.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::testing::Not;

TEST(AeadUtilTest, GetAesCtrCipherForKeySize) {
  for (int i = 0; i < 64; i++) {
    util::StatusOr<const EVP_CIPHER*> cipher = GetAesCtrCipherForKeySize(i);
    if (i == 16) {
      EXPECT_THAT(cipher, IsOkAndHolds(EVP_aes_128_ctr()));
    } else if (i == 32) {
      EXPECT_THAT(cipher, IsOkAndHolds(EVP_aes_256_ctr()));
    } else {
      EXPECT_THAT(cipher.status(), Not(IsOk()));
    }
  }
}

TEST(AeadUtilTest, GetAesGcmCipherForKeySize) {
  for (int i = 0; i < 64; i++) {
    util::StatusOr<const EVP_CIPHER*> cipher = GetAesGcmCipherForKeySize(i);
    if (i == 16) {
      EXPECT_THAT(cipher, IsOkAndHolds(EVP_aes_128_gcm()));
    } else if (i == 32) {
      EXPECT_THAT(cipher, IsOkAndHolds(EVP_aes_256_gcm()));
    } else {
      EXPECT_THAT(cipher.status(), Not(IsOk()));
    }
  }
}

#ifdef OPENSSL_IS_BORINGSSL

TEST(AeadUtilTest, GetAesAeadForKeySize) {
  for (int i = 0; i < 64; i++) {
    util::StatusOr<const EVP_AEAD*> cipher = GetAesGcmAeadForKeySize(i);
    if (i == 16) {
      EXPECT_THAT(cipher, IsOkAndHolds(EVP_aead_aes_128_gcm()));
    } else if (i == 32) {
      EXPECT_THAT(cipher, IsOkAndHolds(EVP_aead_aes_256_gcm()));
    } else {
      EXPECT_THAT(cipher.status(), Not(IsOk()));
    }
  }
}

TEST(AeadUtilTest, GetAesGcmSivAeadCipherForKeySize) {
  for (int i = 0; i < 64; i++) {
    util::StatusOr<const EVP_AEAD*> cipher =
        GetAesGcmSivAeadCipherForKeySize(i);
    if (i == 16) {
      EXPECT_THAT(cipher, IsOkAndHolds(EVP_aead_aes_128_gcm_siv()));
    } else if (i == 32) {
      EXPECT_THAT(cipher, IsOkAndHolds(EVP_aead_aes_256_gcm_siv()));
    } else {
      EXPECT_THAT(cipher.status(), Not(IsOk()));
    }
  }
}

#endif

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
