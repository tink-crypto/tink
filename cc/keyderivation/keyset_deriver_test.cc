// Copyright 2024 Google LLC
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

#include "tink/keyderivation/keyset_deriver.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_proto_serialization.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/keyderivation/internal/prf_based_deriver.h"
#include "tink/keyderivation/keyset_deriver_wrapper.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/primitive_set.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/hkdf_prf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HkdfPrfKey;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

// Hex values from HKDF RFC https://tools.ietf.org/html/rfc5869#appendix-A.2.
static constexpr absl::string_view kOutputKeyMaterialFromRfcVector =
    "b11e398dc80327a1c8e7f78c596a4934"
    "4f012eda2d4efad8a050cc4c19afa97c"
    "59045a99cac7827271cb41c65e590e09"
    "da3275600c2f09b8367793a9aca3db71"
    "cc30c58179ec3e87c14c01d5c1f3434f";

KeyData PrfKeyFromRfcVector() {
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

std::string SaltFromRfcVector() {
  return test::HexDecodeOrDie(
      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
      "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
      "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
      "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
      "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
}

KeysetInfo::KeyInfo PrfBasedDeriverKeyInfo(
    OutputPrefixType output_prefix_type) {
  KeysetInfo::KeyInfo key_info;
  key_info.set_type_url(
      "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
  key_info.set_status(KeyStatusType::ENABLED);
  if (output_prefix_type != OutputPrefixType::RAW) {
    key_info.set_key_id(1010101);
  }
  key_info.set_output_prefix_type(output_prefix_type);
  return key_info;
}

std::unique_ptr<AesGcmKey> CreateAesGcmKey(int key_size,
                                           AesGcmParameters::Variant variant,
                                           absl::string_view secret) {
  AesGcmParameters params = *AesGcmParameters::Builder()
                                 .SetKeySizeInBytes(key_size)
                                 .SetIvSizeInBytes(12)
                                 .SetTagSizeInBytes(16)
                                 .SetVariant(variant)
                                 .Build();
  absl::optional<int> id_requirement = 1010101;
  if (variant == AesGcmParameters::Variant::kNoPrefix) {
    id_requirement = absl::nullopt;
  }
  return std::make_unique<AesGcmKey>(
      *AesGcmKey::Create(params,
                         RestrictedData(test::HexDecodeOrDie(secret),
                                        InsecureSecretKeyAccess::Get()),
                         id_requirement, GetPartialKeyAccess()));
}

struct TestVector {
  KeysetInfo::KeyInfo keyset_deriver_key;
  std::shared_ptr<Key> derived_key;
};

std::vector<TestVector> TestVectors() {
  return {
      {
          PrfBasedDeriverKeyInfo(OutputPrefixType::TINK),
          CreateAesGcmKey(
              /*key_size=*/16,
              /*variant=*/AesGcmParameters::Variant::kTink,
              /*secret=*/kOutputKeyMaterialFromRfcVector.substr(0, 32)),
      },
      {
          PrfBasedDeriverKeyInfo(OutputPrefixType::TINK),
          CreateAesGcmKey(
              /*key_size=*/32,
              /*variant=*/AesGcmParameters::Variant::kTink,
              /*secret=*/kOutputKeyMaterialFromRfcVector.substr(0, 64)),
      },
      {
          PrfBasedDeriverKeyInfo(OutputPrefixType::CRUNCHY),
          CreateAesGcmKey(
              /*key_size=*/16,
              /*variant=*/AesGcmParameters::Variant::kCrunchy,
              /*secret=*/kOutputKeyMaterialFromRfcVector.substr(0, 32)),
      },
      {
          PrfBasedDeriverKeyInfo(OutputPrefixType::RAW),
          CreateAesGcmKey(
              /*key_size=*/32,
              /*variant=*/AesGcmParameters::Variant::kNoPrefix,
              /*secret=*/kOutputKeyMaterialFromRfcVector.substr(0, 64)),
      },
  };
}

using KeysetDeriverTest = TestWithParam<TestVector>;

INSTANTIATE_TEST_SUITE_P(KeysetDeriverTests, KeysetDeriverTest,
                         ValuesIn(TestVectors()));

TEST_P(KeysetDeriverTest, DeriveKeyset) {
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<HkdfPrfKeyManager>(), true),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());
  ASSERT_THAT(RegisterAesGcmProtoSerialization(), IsOk());

  TestVector vector = GetParam();

  // Get KeyTemplate from Parameters for PrfBasedDeriver constructor.
  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              vector.derived_key->GetParameters());
  ASSERT_THAT(serialization, IsOk());
  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());

  // Construct wrapped KeysetDeriver.
  util::StatusOr<std::unique_ptr<KeysetDeriver>> deriver =
      internal::PrfBasedDeriver::New(PrfKeyFromRfcVector(),
                                     proto_serialization->GetKeyTemplate());
  ASSERT_THAT(deriver, IsOk());
  util::StatusOr<PrimitiveSet<KeysetDeriver>> pset =
      PrimitiveSet<KeysetDeriver>::Builder()
          .AddPrimaryPrimitive(*std::move(deriver), vector.keyset_deriver_key)
          .Build();
  ASSERT_THAT(pset, IsOk());
  util::StatusOr<std::unique_ptr<KeysetDeriver>> wrapped_deriver =
      KeysetDeriverWrapper().Wrap(
          std::make_unique<PrimitiveSet<KeysetDeriver>>(*std::move(pset)));
  ASSERT_THAT(wrapped_deriver, IsOk());

  // Derive KeysetHandle.
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      (*wrapped_deriver)->DeriveKeyset(SaltFromRfcVector());
  ASSERT_THAT(handle, IsOk());
  ASSERT_THAT((*handle)->size(), Eq(1));

  EXPECT_THAT(*(*handle)->GetPrimary().GetKey(),
              Eq(std::ref(*vector.derived_key)));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
