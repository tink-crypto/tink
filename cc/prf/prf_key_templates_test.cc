// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/prf/prf_key_templates.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "tink/prf/aes_cmac_prf_key_manager.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_cmac_prf.pb.h"
#include "proto/hmac_prf.pb.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::HkdfPrfKeyFormat;
using ::testing::Eq;
using ::testing::Ref;

TEST(HkdfSha256HkdfTest, Basics) {
  EXPECT_THAT(PrfKeyTemplates::HkdfSha256().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.HkdfPrfKey"));
  EXPECT_THAT(PrfKeyTemplates::HkdfSha256().type_url(),
              Eq(HkdfPrfKeyManager().get_key_type()));
}

TEST(HkdfSha256HkdfTest, OutputPrefixType) {
  EXPECT_THAT(PrfKeyTemplates::HkdfSha256().output_prefix_type(),
              Eq(google::crypto::tink::OutputPrefixType::RAW));
}

TEST(HkdfSha256HkdfTest, MultipleCallsSameReference) {
  EXPECT_THAT(PrfKeyTemplates::HkdfSha256(),
              Ref(PrfKeyTemplates::HkdfSha256()));
}

TEST(HkdfSha256HkdfTest, WorksWithKeyTypeManager) {
  const google::crypto::tink::KeyTemplate& key_template =
      PrfKeyTemplates::HkdfSha256();
  HkdfPrfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(HmacPrfTest, Basics) {
  EXPECT_THAT(PrfKeyTemplates::HmacSha256().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.HmacPrfKey"));
  EXPECT_THAT(PrfKeyTemplates::HmacSha512().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.HmacPrfKey"));
  auto manager = absl::make_unique<HmacPrfKeyManager>();
  EXPECT_THAT(PrfKeyTemplates::HmacSha256().type_url(),
              Eq(manager->get_key_type()));
  google::crypto::tink::HmacPrfKeyFormat format;
  ASSERT_TRUE(format.ParseFromString(PrfKeyTemplates::HmacSha256().value()));
  EXPECT_THAT(manager->ValidateKeyFormat(format), IsOk());
  ASSERT_TRUE(format.ParseFromString(PrfKeyTemplates::HmacSha512().value()));
  EXPECT_THAT(manager->ValidateKeyFormat(format), IsOk());
}

TEST(HmacPrfTest, OutputPrefixType) {
  EXPECT_THAT(PrfKeyTemplates::HmacSha256().output_prefix_type(),
              Eq(google::crypto::tink::OutputPrefixType::RAW));
  EXPECT_THAT(PrfKeyTemplates::HmacSha512().output_prefix_type(),
              Eq(google::crypto::tink::OutputPrefixType::RAW));
}

TEST(HmacPrfTest, MultipleCallsSameReference) {
  EXPECT_THAT(PrfKeyTemplates::HmacSha256(),
              Ref(PrfKeyTemplates::HmacSha256()));
  EXPECT_THAT(PrfKeyTemplates::HmacSha512(),
              Ref(PrfKeyTemplates::HmacSha512()));
}

TEST(CmacPrfTest, Basics) {
  EXPECT_THAT(PrfKeyTemplates::AesCmac().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesCmacPrfKey"));
  auto manager = absl::make_unique<AesCmacPrfKeyManager>();
  EXPECT_THAT(PrfKeyTemplates::AesCmac().type_url(),
              Eq(manager->get_key_type()));
  google::crypto::tink::AesCmacPrfKeyFormat format;
  ASSERT_TRUE(format.ParseFromString(PrfKeyTemplates::AesCmac().value()));
  EXPECT_THAT(manager->ValidateKeyFormat(format), IsOk());
}

TEST(CmacPrfTest, OutputPrefixType) {
  EXPECT_THAT(PrfKeyTemplates::AesCmac().output_prefix_type(),
              Eq(google::crypto::tink::OutputPrefixType::RAW));
}

TEST(CmacPrfTest, MultipleCallsSameReference) {
  EXPECT_THAT(PrfKeyTemplates::AesCmac(), Ref(PrfKeyTemplates::AesCmac()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
