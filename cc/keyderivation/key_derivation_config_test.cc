// Copyright 2020 Google LLC
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

#include "tink/keyderivation/key_derivation_config.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/keyderivation/key_derivation_key_templates.h"
#include "tink/keyderivation/keyset_deriver.h"
#include "tink/prf/prf_key_templates.h"
#include "tink/registry.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::IsOk;
using ::testing::Not;

TEST(KeyDerivationConfigTest, Register) {
  Registry::Reset();

  EXPECT_THAT(KeyDerivationKeyTemplates::CreatePrfBasedKeyTemplate(
                  PrfKeyTemplates::HkdfSha256(), AeadKeyTemplates::Aes256Gcm()),
              Not(IsOk()));

  ASSERT_THAT(KeyDerivationConfig::Register(), IsOk());
  ASSERT_THAT(AeadConfig::Register(), IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());

  util::StatusOr<::google::crypto::tink::KeyTemplate> templ =
      KeyDerivationKeyTemplates::CreatePrfBasedKeyTemplate(
          PrfKeyTemplates::HkdfSha256(), AeadKeyTemplates::Aes256Gcm());
  ASSERT_THAT(templ, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(*templ);
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<KeysetDeriver>> deriver =
      (*handle)->GetPrimitive<crypto::tink::KeysetDeriver>(
          ConfigGlobalRegistry());
  ASSERT_THAT(deriver, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> derived_handle =
      (*deriver)->DeriveKeyset("salty");
  ASSERT_THAT(derived_handle, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> aead =
      (*derived_handle)
          ->GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(aead, IsOk());
  std::string plaintext = "plaintext";
  std::string ad = "ad";
  util::StatusOr<std::string> ciphertext = (*aead)->Encrypt(plaintext, ad);
  ASSERT_THAT(ciphertext, IsOk());
  util::StatusOr<std::string> got = (*aead)->Decrypt(*ciphertext, ad);
  ASSERT_THAT(got, IsOk());
  EXPECT_EQ(plaintext, *got);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
