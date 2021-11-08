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
///////////////////////////////////////////////////////////////////////////////

#include "tink/hybrid/ecies_aead_hkdf_dem_helper.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/registry.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::AeadOrDaead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::StatusOr;
using ::testing::HasSubstr;

// Checks whether Decrypt(Encrypt(message)) == message with the given dem.
crypto::tink::util::Status EncryptThenDecrypt(
    const AeadOrDaead& dem, absl::string_view message,
    absl::string_view associated_data) {
  StatusOr<std::string> encryption_or = dem.Encrypt(message, associated_data);
  if (!encryption_or.status().ok()) return encryption_or.status();
  StatusOr<std::string> decryption_or =
      dem.Decrypt(encryption_or.ValueOrDie(), associated_data);
  if (!decryption_or.status().ok()) return decryption_or.status();
  if (decryption_or.ValueOrDie() != message) {
    return crypto::tink::util::Status(absl::StatusCode::kInternal,
                                      "Message/Decryption mismatch");
  }
  return util::OkStatus();
}

TEST(EciesAeadHkdfDemHelperTest, InvalidKey) {
  google::crypto::tink::KeyTemplate dem_key_template;
  dem_key_template.set_type_url("some.type.url/that.is.not.supported");
  auto result = EciesAeadHkdfDemHelper::New(dem_key_template);
  EXPECT_THAT(EciesAeadHkdfDemHelper::New(dem_key_template).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unsupported DEM")));
}

TEST(EciesAeadHkdfDemHelperTest, DemHelperWithSomeAeadKeyType) {
  google::crypto::tink::AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  std::unique_ptr<AesGcmKeyManager> key_manager(new AesGcmKeyManager());
  std::string dem_key_type = key_manager->get_key_type();
  ASSERT_THAT(Registry::RegisterKeyTypeManager(std::move(key_manager), true),
              IsOk());

  google::crypto::tink::KeyTemplate dem_key_template;
  dem_key_template.set_type_url(dem_key_type);
  dem_key_template.set_value(key_format.SerializeAsString());

  auto dem_helper_or = EciesAeadHkdfDemHelper::New(dem_key_template);
  ASSERT_THAT(dem_helper_or.status(), IsOk());
  auto dem_helper = std::move(dem_helper_or.ValueOrDie());

  util::SecretData key128 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  StatusOr<std::unique_ptr<AeadOrDaead>> aead_or_daead_result_or =
      dem_helper->GetAeadOrDaead(key128);
  ASSERT_THAT(aead_or_daead_result_or.status(), IsOk());

  auto aead_or_daead = std::move(aead_or_daead_result_or.ValueOrDie());
  EXPECT_THAT(EncryptThenDecrypt(*aead_or_daead, "test_plaintext", "test_ad"),
              IsOk());
}

TEST(EciesAeadHkdfDemHelperTest, DemHelperWithSomeDeterministicAeadKeyType) {
  google::crypto::tink::AesSivKeyFormat key_format;
  key_format.set_key_size(64);
  std::unique_ptr<AesSivKeyManager> key_manager(new AesSivKeyManager());
  std::string dem_key_type = key_manager->get_key_type();
  ASSERT_THAT(Registry::RegisterKeyTypeManager(std::move(key_manager), true),
              IsOk());

  google::crypto::tink::KeyTemplate dem_key_template;
  dem_key_template.set_type_url(dem_key_type);
  dem_key_template.set_value(key_format.SerializeAsString());

  auto dem_helper_or = EciesAeadHkdfDemHelper::New(dem_key_template);
  ASSERT_THAT(dem_helper_or.status(), IsOk());
  auto dem_helper = std::move(dem_helper_or.ValueOrDie());

  util::SecretData key128 = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00010203"
      "0405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));
  StatusOr<std::unique_ptr<AeadOrDaead>> aead_or_daead_result_or =
      dem_helper->GetAeadOrDaead(key128);
  ASSERT_THAT(aead_or_daead_result_or.status(), IsOk());

  auto aead_or_daead = std::move(aead_or_daead_result_or.ValueOrDie());
  EXPECT_THAT(EncryptThenDecrypt(*aead_or_daead, "test_plaintext", "test_ad"),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
