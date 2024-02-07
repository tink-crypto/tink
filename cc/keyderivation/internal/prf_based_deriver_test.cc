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

#include "tink/keyderivation/internal/prf_based_deriver.h"

#include <memory>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/keyderivation/keyset_deriver.h"
#include "tink/keyset_handle.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/registry.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HkdfPrfKey;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::Ne;
using ::testing::SizeIs;
using ::testing::Test;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

class PrfBasedDeriverTest : public Test {
 public:
  void SetUp() override {
    Registry::Reset();
    ASSERT_THAT(Registry::RegisterKeyTypeManager(
                    absl::make_unique<HkdfPrfKeyManager>(), true),
                IsOk());
  }

  KeyData valid_prf_key_data_ = PrfKeyData();
  HkdfPrfKey valid_prf_key_ = PrfKey();

 private:
  HkdfPrfKey PrfKey() {
    HkdfPrfKey prf_key;
    prf_key.set_version(0);
    prf_key.mutable_params()->set_hash(HashType::SHA256);
    prf_key.mutable_params()->set_salt("");
    prf_key.set_key_value("0123456789abcdef0123456789abcdef");
    return prf_key;
  }

  KeyData PrfKeyData() { return test::AsKeyData(PrfKey(), KeyData::SYMMETRIC); }
};

TEST_F(PrfBasedDeriverTest, New) {
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());
  EXPECT_THAT(
      PrfBasedDeriver::New(valid_prf_key_data_, AeadKeyTemplates::Aes128Gcm()),
      IsOk());
}

TEST_F(PrfBasedDeriverTest, NewWithInvalidPrfKey) {
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());
  HkdfPrfKey invalid_prf_key = valid_prf_key_;
  invalid_prf_key.mutable_params()->set_hash(HashType::UNKNOWN_HASH);
  EXPECT_THAT(
      PrfBasedDeriver::New(test::AsKeyData(invalid_prf_key, KeyData::SYMMETRIC),
                           AeadKeyTemplates::Aes128Gcm())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(PrfBasedDeriverTest, NewWithInvalidDerivedKeyTemplate) {
  KeyTemplate invalid_derived_template;
  invalid_derived_template.set_type_url("i.do.not.exist");
  EXPECT_THAT(PrfBasedDeriver::New(
                  test::AsKeyData(valid_prf_key_data_, KeyData::SYMMETRIC),
                  invalid_derived_template)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST_F(PrfBasedDeriverTest, DeriveKeysetWithGlobalRegistryPlaceholderValues) {
  ASSERT_THAT(
      PrfBasedDeriver::New(valid_prf_key_data_, AeadKeyTemplates::Aes128Gcm())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());
  util::StatusOr<std::unique_ptr<KeysetDeriver>> deriver =
      PrfBasedDeriver::New(valid_prf_key_data_, AeadKeyTemplates::Aes128Gcm());
  ASSERT_THAT(deriver, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      (*deriver)->DeriveKeyset("salt");
  ASSERT_THAT(handle, IsOk());
  ASSERT_THAT(**handle, SizeIs(1));

  Keyset keyset = CleartextKeysetHandle::GetKeyset(**handle);
  ASSERT_THAT(keyset.key(), SizeIs(1));
  EXPECT_THAT(keyset.primary_key_id(), Eq(0));
  EXPECT_THAT(keyset.key(0).status(), Eq(KeyStatusType::UNKNOWN_STATUS));
  EXPECT_THAT(keyset.key(0).key_id(), Eq(keyset.primary_key_id()));
  EXPECT_THAT(keyset.key(0).output_prefix_type(),
              Eq(OutputPrefixType::UNKNOWN_PREFIX));
}

TEST_F(PrfBasedDeriverTest, DeriveKeysetWithDifferentPrfKeys) {
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());

  google::crypto::tink::AesGcmKey derived_key_0;
  google::crypto::tink::AesGcmKey derived_key_1;
  KeyTemplate key_template = AeadKeyTemplates::Aes128Gcm();
  std::string salt = "salt";
  {
    util::StatusOr<std::unique_ptr<KeysetDeriver>> deriver =
        PrfBasedDeriver::New(valid_prf_key_data_, key_template);
    ASSERT_THAT(deriver, IsOk());
    util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
        (*deriver)->DeriveKeyset(salt);
    ASSERT_THAT(handle, IsOk());
    Keyset keyset = CleartextKeysetHandle::GetKeyset(**handle);
    ASSERT_TRUE(
        derived_key_0.ParseFromString(keyset.key(0).key_data().value()));
  }
  {
    HkdfPrfKey different_prf_key = valid_prf_key_;
    different_prf_key.set_key_value(subtle::Random::GetRandomBytes(32));
    KeyData different_key_data =
        test::AsKeyData(different_prf_key, KeyData::SYMMETRIC);
    util::StatusOr<std::unique_ptr<KeysetDeriver>> deriver =
        PrfBasedDeriver::New(different_key_data, key_template);
    ASSERT_THAT(deriver, IsOk());
    util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
        (*deriver)->DeriveKeyset(salt);
    ASSERT_THAT(handle, IsOk());
    Keyset keyset = CleartextKeysetHandle::GetKeyset(**handle);
    ASSERT_TRUE(
        derived_key_1.ParseFromString(keyset.key(0).key_data().value()));
  }
  EXPECT_THAT(derived_key_0.key_value(), SizeIs(16));
  EXPECT_THAT(derived_key_1.key_value(), SizeIs(16));
  EXPECT_THAT(derived_key_0.key_value(), Ne(derived_key_1.key_value()));
}

TEST_F(PrfBasedDeriverTest, DeriveKeysetWithDifferentSalts) {
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());
  util::StatusOr<std::unique_ptr<KeysetDeriver>> deriver =
      PrfBasedDeriver::New(valid_prf_key_data_, AeadKeyTemplates::Aes128Gcm());
  ASSERT_THAT(deriver, IsOk());

  google::crypto::tink::AesGcmKey derived_key_0;
  google::crypto::tink::AesGcmKey derived_key_1;
  {
    util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
        (*deriver)->DeriveKeyset("salt");
    ASSERT_THAT(handle, IsOk());
    Keyset keyset = CleartextKeysetHandle::GetKeyset(**handle);
    ASSERT_TRUE(
        derived_key_0.ParseFromString(keyset.key(0).key_data().value()));
  }
  {
    util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
        (*deriver)->DeriveKeyset("different_salt");
    ASSERT_THAT(handle, IsOk());
    Keyset keyset = CleartextKeysetHandle::GetKeyset(**handle);
    ASSERT_TRUE(
        derived_key_1.ParseFromString(keyset.key(0).key_data().value()));
  }
  EXPECT_THAT(derived_key_0.key_value(), SizeIs(16));
  EXPECT_THAT(derived_key_1.key_value(), SizeIs(16));
  EXPECT_THAT(derived_key_0.key_value(), Ne(derived_key_1.key_value()));
}

// Test vector from https://tools.ietf.org/html/rfc5869#appendix-A.2.
class PrfBasedDeriverRfcVectorTest : public Test {
 public:
  static void SetUpTestSuite() {
    Registry::Reset();
    ASSERT_THAT(Registry::RegisterKeyTypeManager(
                    absl::make_unique<HkdfPrfKeyManager>(), true),
                IsOk());
  }

  KeyData prf_key_from_rfc_vector_ = PrfKeyData();
  std::string salt_ = test::HexDecodeOrDie(
      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
      "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
      "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
      "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
      "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
  // The first 32 bytes of the vector's output key material (OKM).
  std::string derived_key_value_ =
      "b11e398dc80327a1c8e7f78c596a4934"
      "4f012eda2d4efad8a050cc4c19afa97c";

 private:
  KeyData PrfKeyData() {
    HkdfPrfKey prf_key;
    prf_key.set_version(0);
    prf_key.mutable_params()->set_hash(HashType::SHA256);
    prf_key.mutable_params()->set_salt(
        test::HexDecodeOrDie("606162636465666768696a6b6c6d6e6f"
                             "707172737475767778797a7b7c7d7e7f"
                             "808182838485868788898a8b8c8d8e8f"
                             "909192939495969798999a9b9c9d9e9f"
                             "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"));
    prf_key.set_key_value(
        test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"
                             "101112131415161718191a1b1c1d1e1f"
                             "202122232425262728292a2b2c2d2e2f"
                             "303132333435363738393a3b3c3d3e3f"
                             "404142434445464748494a4b4c4d4e4f"));
    return test::AsKeyData(prf_key, KeyData::SYMMETRIC);
  }
};

TEST_F(PrfBasedDeriverRfcVectorTest, DeriveKeysetWithGlobalRegistry) {
  ASSERT_THAT(PrfBasedDeriver::New(prf_key_from_rfc_vector_,
                                   AeadKeyTemplates::Aes256Gcm())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());
  util::StatusOr<std::unique_ptr<KeysetDeriver>> deriver = PrfBasedDeriver::New(
      prf_key_from_rfc_vector_, AeadKeyTemplates::Aes256Gcm());
  ASSERT_THAT(deriver, IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      (*deriver)->DeriveKeyset(salt_);
  ASSERT_THAT(handle, IsOk());

  Keyset keyset = CleartextKeysetHandle::GetKeyset(**handle);
  ASSERT_THAT(keyset.key(), SizeIs(1));
  EXPECT_THAT(keyset.key(0).key_data().type_url(),
              Eq(AesGcmKeyManager().get_key_type()));
  EXPECT_THAT(keyset.key(0).key_data().key_material_type(),
              Eq(AesGcmKeyManager().key_material_type()));

  google::crypto::tink::AesGcmKey derived_key;
  ASSERT_TRUE(derived_key.ParseFromString(keyset.key(0).key_data().value()));
  EXPECT_THAT(derived_key.version(), Eq(AesGcmKeyManager().get_version()));
  EXPECT_THAT(test::HexEncode(derived_key.key_value()), Eq(derived_key_value_));
}

struct PrfBasedDeriverJavaVector {
  std::string prf_key_value;
  std::string deriving_salt;
  std::string derived_key_value;
};

// Test vectors generated with the Tink Java implementation.
std::vector<PrfBasedDeriverJavaVector> GetPrfBasedDeriverJavaVectors() {
  return {
      {
          /*prf_key_value=*/test::HexDecodeOrDie(
              "a1a2a3a4a5a6a7a8a9aaabacadaeafb1b2b3b4b5b6b7b8b9babbbcbdbebf"
              "c1c2c3c4c5c6c7c8c9cacbcccdcecfc1c2c3c4c5c6c7c8c9cacbcccdcecf"
              "00"),
          /*deriving_salt=*/test::HexDecodeOrDie("1122334455"),
          /*derived_key_value=*/"31c449af66b669b9963ef2df30dfe5f9",
      },
      {
          /*prf_key_value=*/test::HexDecodeOrDie(
              "c1c2c3c4c5c6c7c8c9cacbcccdcecfc1c2c3c4c5c6c7c8c9cacbcccdcecf"
              "a1a2a3a4a5a6a7a8a9aaabacadaeafb1b2b3b4b5b6b7b8b9babbbcbdbebf"),
          /*deriving_salt=*/test::HexDecodeOrDie("00"),
          /*derived_key_value=*/"887af0808c1855eba1594bf540adb957",
      },
      {
          /*prf_key_value=*/test::HexDecodeOrDie(
              "c1c2c3c4c5c6c7c8c9cacbcccdcecfc1c2c3c4c5c6c7c8c9cacbcccdcecf"
              "a1a2a3a4a5a6a7a8a9aaabacadaeafb1b2b3b4b5b6b7b8b9babbbcbdbebf"),
          /*deriving_salt=*/"",
          /*derived_key_value=*/"fb2b448c2595caf75129e282af758bf1",
      },
  };
}

using PrfBasedDeriverJavaVectorsTest = TestWithParam<PrfBasedDeriverJavaVector>;

INSTANTIATE_TEST_SUITE_P(PrfBasedDeriverJavaVectorsTests,
                         PrfBasedDeriverJavaVectorsTest,
                         ValuesIn(GetPrfBasedDeriverJavaVectors()));

TEST_P(PrfBasedDeriverJavaVectorsTest, DeriveKeysetWithGlobalRegistry) {
  Registry::Reset();
  PrfBasedDeriverJavaVector test_vector = GetParam();
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<HkdfPrfKeyManager>(), true),
              IsOk());

  HkdfPrfKey prf_key;
  prf_key.set_version(0);
  prf_key.mutable_params()->set_hash(HashType::SHA512);
  prf_key.set_key_value(test_vector.prf_key_value);
  KeyData key_data = test::AsKeyData(prf_key, KeyData::SYMMETRIC);

  ASSERT_THAT(
      PrfBasedDeriver::New(key_data, AeadKeyTemplates::Aes128Gcm()).status(),
      StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());
  util::StatusOr<std::unique_ptr<KeysetDeriver>> deriver =
      PrfBasedDeriver::New(key_data, AeadKeyTemplates::Aes128Gcm());
  ASSERT_THAT(deriver, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      (*deriver)->DeriveKeyset(test_vector.deriving_salt);
  ASSERT_THAT(handle, IsOk());

  Keyset keyset = CleartextKeysetHandle::GetKeyset(**handle);
  google::crypto::tink::AesGcmKey derived_key;
  ASSERT_TRUE(derived_key.ParseFromString(keyset.key(0).key_data().value()));
  EXPECT_THAT(derived_key.version(), Eq(AesGcmKeyManager().get_version()));
  EXPECT_THAT(test::HexEncode(derived_key.key_value()),
              Eq(test_vector.derived_key_value));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
