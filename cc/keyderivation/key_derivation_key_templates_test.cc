// Copyright 2019 Google LLC
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

#include "tink/keyderivation/key_derivation_key_templates.h"

#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/keyderivation/internal/prf_based_deriver_key_manager.h"
#include "tink/keyderivation/keyset_deriver_wrapper.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/prf/prf_key_templates.h"
#include "tink/registry.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/prf_based_deriver.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::PrfBasedDeriverKeyFormat;
using ::testing::Eq;
using ::testing::Not;

class KeyDerivationKeyTemplatesTest : public ::testing::Test {
 protected:
  void TearDown() override { Registry::Reset(); }
};

TEST_F(KeyDerivationKeyTemplatesTest, CreatePrfBasedKeyTemplate) {
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<KeysetDeriverWrapper>()),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<internal::PrfBasedDeriverKeyManager>(),
                  /*new_key_allowed=*/true),
              IsOk());
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(absl::make_unique<HkdfPrfKeyManager>(),
                                       /*new_key_allowed=*/true),
      IsOk());
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(absl::make_unique<AesGcmKeyManager>(),
                                       /*new_key_allowed=*/true),
      IsOk());

  std::vector<OutputPrefixType> output_prefix_types = {
      OutputPrefixType::RAW, OutputPrefixType::TINK, OutputPrefixType::LEGACY};
  for (OutputPrefixType output_prefix_type : output_prefix_types) {
    KeyTemplate derived_key_template = AeadKeyTemplates::Aes256Gcm();
    derived_key_template.set_output_prefix_type(output_prefix_type);
    util::StatusOr<KeyTemplate> key_template =
        KeyDerivationKeyTemplates::CreatePrfBasedKeyTemplate(
            PrfKeyTemplates::HkdfSha256(), derived_key_template);

    ASSERT_THAT(key_template, IsOk());
    EXPECT_THAT(
        key_template->type_url(),
        Eq("type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey"));
    EXPECT_THAT(key_template->type_url(),
                Eq(internal::PrfBasedDeriverKeyManager().get_key_type()));
    EXPECT_THAT(key_template->output_prefix_type(), Eq(output_prefix_type));

    PrfBasedDeriverKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template->value()));
    EXPECT_THAT(
        internal::PrfBasedDeriverKeyManager().ValidateKeyFormat(key_format),
        IsOk());
  }
}

TEST_F(KeyDerivationKeyTemplatesTest, CreatePrfBasedKeyTemplateInvalidPrfKey) {
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<KeysetDeriverWrapper>()),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<internal::PrfBasedDeriverKeyManager>(),
                  /*new_key_allowed=*/true),
              IsOk());
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(absl::make_unique<HkdfPrfKeyManager>(),
                                       /*new_key_allowed=*/true),
      IsOk());
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(absl::make_unique<AesGcmKeyManager>(),
                                       /*new_key_allowed=*/true),
      IsOk());

  EXPECT_THAT(KeyDerivationKeyTemplates::CreatePrfBasedKeyTemplate(
                  AeadKeyTemplates::Aes256Gcm(), AeadKeyTemplates::Aes256Gcm())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST_F(KeyDerivationKeyTemplatesTest,
       CreatePrfBasedKeyTemplateInvalidDerivedKeyTemplate) {
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<KeysetDeriverWrapper>()),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<internal::PrfBasedDeriverKeyManager>(),
                  /*new_key_allowed=*/true),
              IsOk());
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(absl::make_unique<HkdfPrfKeyManager>(),
                                       /*new_key_allowed=*/true),
      IsOk());
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(absl::make_unique<AesGcmKeyManager>(),
                                       /*new_key_allowed=*/true),
      IsOk());

  util::StatusOr<KeyTemplate> derived_key_template =
      KeyDerivationKeyTemplates::CreatePrfBasedKeyTemplate(
          PrfKeyTemplates::HkdfSha256(), AeadKeyTemplates::Aes256Gcm());
  ASSERT_THAT(derived_key_template, IsOk());
  EXPECT_THAT(KeyDerivationKeyTemplates::CreatePrfBasedKeyTemplate(
                  PrfKeyTemplates::HkdfSha256(), *derived_key_template)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST_F(KeyDerivationKeyTemplatesTest,
       CreatePrfBasedKeyTemplateNoPrfBasedDeriverKeyManager) {
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<KeysetDeriverWrapper>()),
              IsOk());
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(absl::make_unique<HkdfPrfKeyManager>(),
                                       /*new_key_allowed=*/true),
      IsOk());
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(absl::make_unique<AesGcmKeyManager>(),
                                       /*new_key_allowed=*/true),
      IsOk());

  EXPECT_THAT(KeyDerivationKeyTemplates::CreatePrfBasedKeyTemplate(
                  PrfKeyTemplates::HkdfSha256(), AeadKeyTemplates::Aes256Gcm()),
              Not(IsOk()));
}

TEST_F(KeyDerivationKeyTemplatesTest,
       CreatePrfBasedKeyTemplateNoHkdfPrfKeyManager) {
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<KeysetDeriverWrapper>()),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<internal::PrfBasedDeriverKeyManager>(),
                  /*new_key_allowed=*/true),
              IsOk());
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(absl::make_unique<AesGcmKeyManager>(),
                                       /*new_key_allowed=*/true),
      IsOk());

  EXPECT_THAT(KeyDerivationKeyTemplates::CreatePrfBasedKeyTemplate(
                  PrfKeyTemplates::HkdfSha256(), AeadKeyTemplates::Aes256Gcm()),
              Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
