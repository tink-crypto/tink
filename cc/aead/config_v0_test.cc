// Copyright 2023 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/aead/config_v0.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/aead.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/key_gen_config_v0.h"
#include "tink/internal/ssl_util.h"
#include "tink/keyset_handle.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::google::crypto::tink::KeyTemplate;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::Values;

using ConfigV0Test = TestWithParam<KeyTemplate>;
using ConfigV0BoringSslTest = TestWithParam<KeyTemplate>;

// For key type support when using BoringSSL or OpenSSL, see
// https://developers.google.com/tink/supported-key-types#aead.
INSTANTIATE_TEST_SUITE_P(ConfigV0TestSuite, ConfigV0Test,
                         Values(AeadKeyTemplates::Aes128CtrHmacSha256(),
                                AeadKeyTemplates::Aes128Eax(),
                                AeadKeyTemplates::Aes128Gcm()));
INSTANTIATE_TEST_SUITE_P(ConfigV0BoringSslTestSuite, ConfigV0BoringSslTest,
                         Values(AeadKeyTemplates::Aes128GcmSiv(),
                                AeadKeyTemplates::XChaCha20Poly1305()));

TEST_P(ConfigV0Test, GetPrimitive) {
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), KeyGenConfigAeadV0());
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> aead =
      (*handle)->GetPrimitive<Aead>(ConfigAeadV0());
  ASSERT_THAT(aead, IsOk());

  std::string plaintext = "plaintext";
  util::StatusOr<std::string> ciphertext = (*aead)->Encrypt(plaintext, "ad");
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, "ad"), IsOkAndHolds(plaintext));
}

TEST_P(ConfigV0BoringSslTest, GetPrimitive) {
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), KeyGenConfigAeadV0());
  ASSERT_THAT(handle, IsOk());

  // Fails if using OpenSSL.
  if (!internal::IsBoringSsl()) {
    EXPECT_THAT((*handle)->GetPrimitive<Aead>(ConfigAeadV0()), Not(IsOk()));
    return;
  }

  util::StatusOr<std::unique_ptr<Aead>> aead =
      (*handle)->GetPrimitive<Aead>(ConfigAeadV0());
  ASSERT_THAT(aead, IsOk());

  std::string plaintext = "plaintext";
  util::StatusOr<std::string> ciphertext = (*aead)->Encrypt(plaintext, "ad");
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, "ad"), IsOkAndHolds(plaintext));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
