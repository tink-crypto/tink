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

#include "tink/keyderivation/internal/key_derivers.h"

#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/aes_eax_proto_serialization.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_proto_serialization.h"
#include "tink/input_stream.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_handle_builder.h"
#include "tink/partial_key_access.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/prf/hkdf_streaming_prf.h"
#include "tink/subtle/prf/streaming_prf.h"
#include "tink/subtle/random.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm.pb.h"
#include "proto/common.pb.h"
#include "proto/hkdf_prf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HkdfPrfKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::SizeIs;
using ::testing::Test;

class KeyDeriversTest : public Test {
 protected:
  void SetUp() override {
    util::StatusOr<std::unique_ptr<StreamingPrf>> streaming_prf =
        subtle::HkdfStreamingPrf::New(
            subtle::HashType::SHA256,
            util::SecretDataFromStringView(subtle::Random::GetRandomBytes(32)),
            "salty");
    ASSERT_THAT(streaming_prf, IsOk());
    randomness_ = (*streaming_prf)->ComputePrf("input");
  }
  std::unique_ptr<InputStream> randomness_;
};

TEST_F(KeyDeriversTest, DeriveKey) {
  int key_size = 16;
  util::StatusOr<AesGcmParameters> params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(key_size)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());
  util::StatusOr<std::unique_ptr<Key>> generic_key =
      DeriveKey(*params, randomness_.get());
  ASSERT_THAT(generic_key, IsOk());

  const AesGcmKey* key =
      dynamic_cast<const AesGcmKey*>(&**std::move(generic_key));
  ASSERT_THAT(key, NotNull());
  EXPECT_THAT(key->GetIdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT(key->GetOutputPrefix(), Eq(""));
  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), SizeIs(key_size));

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(*key,
                                                        KeyStatus::kEnabled,
                                                        /*is_primary=*/true);
  EXPECT_THAT(KeysetHandleBuilder().AddEntry(std::move(entry)).Build(), IsOk());
}

TEST_F(KeyDeriversTest, MissingKeyDeriverFn) {
  ASSERT_THAT(RegisterAesEaxProtoSerialization(), IsOk());
  util::StatusOr<AesEaxParameters> params =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(12)
          .SetVariant(AesEaxParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT(DeriveKey(*params, randomness_.get()).status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST_F(KeyDeriversTest, InsufficientRandomness) {
  util::StatusOr<AesGcmParameters> params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());
  util::IstreamInputStream insufficient_randomness{
      absl::make_unique<std::stringstream>("0123456789")};
  util::StatusOr<std::unique_ptr<Key>> key =
      DeriveKey(*params, &insufficient_randomness);
  ASSERT_THAT(key.status(), StatusIs(absl::StatusCode::kOutOfRange));
}

// Test vector from https://tools.ietf.org/html/rfc5869#appendix-A.2.
class KeyDeriversRfcVectorTest : public Test {
 public:
  void SetUp() override {
    Registry::Reset();
    ASSERT_THAT(Registry::RegisterKeyTypeManager(
                    absl::make_unique<HkdfPrfKeyManager>(), true),
                IsOk());

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
    KeyData key_data = test::AsKeyData(prf_key, KeyData::SYMMETRIC);

    util::StatusOr<std::unique_ptr<StreamingPrf>> streaming_prf =
        Registry::GetPrimitive<StreamingPrf>(key_data);
    ASSERT_THAT(streaming_prf, IsOk());
    util::StatusOr<std::unique_ptr<StreamingPrf>> same_streaming_prf =
        Registry::GetPrimitive<StreamingPrf>(key_data);
    ASSERT_THAT(same_streaming_prf, IsOk());

    std::string salt = test::HexDecodeOrDie(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    randomness_from_rfc_vector_ = (*streaming_prf)->ComputePrf(salt);
    same_randomness_from_rfc_vector_ = (*same_streaming_prf)->ComputePrf(salt);
  }

  std::unique_ptr<InputStream> randomness_from_rfc_vector_;
  std::unique_ptr<InputStream> same_randomness_from_rfc_vector_;
  // The first 32 bytes of the vector's output key material (OKM).
  std::string derived_key_value_ =
      "b11e398dc80327a1c8e7f78c596a4934"
      "4f012eda2d4efad8a050cc4c19afa97c";
};

TEST_F(KeyDeriversRfcVectorTest, AesGcm) {
  // Derive key with hard-coded map.
  util::StatusOr<AesGcmParameters> params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());
  util::StatusOr<std::unique_ptr<Key>> generic_key =
      DeriveKey(*params, randomness_from_rfc_vector_.get());
  ASSERT_THAT(generic_key, IsOk());
  const AesGcmKey* key =
      dynamic_cast<const AesGcmKey*>(&**std::move(generic_key));
  ASSERT_THAT(key, NotNull());
  std::string key_bytes =
      test::HexEncode(key->GetKeyBytes(GetPartialKeyAccess())
                          .GetSecret(InsecureSecretKeyAccess::Get()));
  ASSERT_THAT(key_bytes, Eq(derived_key_value_));

  // Derive key with AesGcmKeyManager.
  ASSERT_THAT(RegisterAesGcmProtoSerialization(), IsOk());
  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialization, IsOk());
  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  AesGcmKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  util::StatusOr<google::crypto::tink::AesGcmKey> proto_key =
      AesGcmKeyManager().DeriveKey(key_format,
                                   same_randomness_from_rfc_vector_.get());
  ASSERT_THAT(proto_key, IsOk());
  std::string proto_key_bytes = test::HexEncode(proto_key->key_value());
  ASSERT_THAT(proto_key_bytes, Eq(derived_key_value_));

  EXPECT_THAT(key_bytes, Eq(proto_key_bytes));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
