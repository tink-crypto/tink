// Copyright 2024 Google LLC
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

#include "tink/aead/aes_ctr_hmac_aead_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_ctr_hmac_aead_key.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_ctr.pb.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesCtrHmacAeadKeyFormat;
using ::google::crypto::tink::AesCtrKey;
using ::google::crypto::tink::AesCtrKeyFormat;
using ::google::crypto::tink::AesCtrParams;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HmacKey;
using ::google::crypto::tink::HmacKeyFormat;
using ::google::crypto::tink::HmacParams;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";

struct TestCase {
  int aes_key_size;
  int hmac_key_size;
  int iv_size;
  int tag_size;
  AesCtrHmacAeadParameters::HashType hash_type;
  HashType proto_hash_type;
  AesCtrHmacAeadParameters::Variant variant;
  OutputPrefixType output_prefix_type;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

class AesCtrHmacAeadProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  AesCtrHmacAeadProtoSerializationTest() {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

INSTANTIATE_TEST_SUITE_P(
    AesCtrHmacAeadKeyBuildTestSuite, AesCtrHmacAeadProtoSerializationTest,
    Values(TestCase{/*aes_key_size=*/16, /*hmac_key_size=*/16,
                    /*iv_size=*/12, /*tag_size=*/28,
                    AesCtrHmacAeadParameters::HashType::kSha256,
                    HashType::SHA256, AesCtrHmacAeadParameters::Variant::kTink,
                    OutputPrefixType::TINK,
                    /*id_requirement=*/0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{/*aes_key_size=*/24, /*hmac_key_size=*/32,
                    /*iv_size=*/16, /*tag_size=*/32,
                    AesCtrHmacAeadParameters::HashType::kSha384,
                    HashType::SHA384,
                    AesCtrHmacAeadParameters::Variant::kCrunchy,
                    OutputPrefixType::CRUNCHY,
                    /*id_requirement=*/0x01030005,
                    std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{/*aes_key_size=*/32, /*hmac_key_size=*/16,
                    /*iv_size=*/16, /*tag_size=*/48,
                    AesCtrHmacAeadParameters::HashType::kSha512,
                    HashType::SHA512,
                    AesCtrHmacAeadParameters::Variant::kNoPrefix,
                    OutputPrefixType::RAW,
                    /*id_requirement=*/absl::nullopt, ""}));

AesCtrHmacAeadKeyFormat BuildAesCtrHmacAeadKeyFormat(int aes_key_size,
                                                     int hmac_key_size,
                                                     int iv_size, int tag_size,
                                                     HashType proto_hash_type,
                                                     int hmac_version) {
  AesCtrHmacAeadKeyFormat aes_ctr_hmac_aead_key_format;
  HmacKeyFormat& hmac_key_format =
      *aes_ctr_hmac_aead_key_format.mutable_hmac_key_format();
  AesCtrKeyFormat& aes_ctr_key_format =
      *aes_ctr_hmac_aead_key_format.mutable_aes_ctr_key_format();

  AesCtrParams& aes_ctr_params = *aes_ctr_key_format.mutable_params();
  aes_ctr_params.set_iv_size(iv_size);
  aes_ctr_key_format.set_key_size(aes_key_size);

  HmacParams& hmac_params = *hmac_key_format.mutable_params();
  hmac_params.set_hash(proto_hash_type);
  hmac_params.set_tag_size(tag_size);
  hmac_key_format.set_key_size(hmac_key_size);
  hmac_key_format.set_version(hmac_version);

  return aes_ctr_hmac_aead_key_format;
}

google::crypto::tink::AesCtrHmacAeadKey BuildAesCtrHmacAeadKey(
    absl::string_view aes_key_bytes, absl::string_view hmac_key_bytes,
    int iv_size, int tag_size, HashType proto_hash_type, int aes_ctr_version,
    int hmac_version) {
  google::crypto::tink::AesCtrHmacAeadKey aes_ctr_hmac_aead_key;
  HmacKey& hmac_key = *aes_ctr_hmac_aead_key.mutable_hmac_key();
  AesCtrKey& aes_ctr_key = *aes_ctr_hmac_aead_key.mutable_aes_ctr_key();

  AesCtrParams& aes_ctr_params = *aes_ctr_key.mutable_params();
  aes_ctr_params.set_iv_size(iv_size);
  aes_ctr_key.set_key_value(aes_key_bytes);
  aes_ctr_key.set_version(aes_ctr_version);

  HmacParams& hmac_params = *hmac_key.mutable_params();
  hmac_params.set_hash(proto_hash_type);
  hmac_params.set_tag_size(tag_size);
  hmac_key.set_key_value(hmac_key_bytes);
  hmac_key.set_version(hmac_version);

  return aes_ctr_hmac_aead_key;
}

TEST_F(AesCtrHmacAeadProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());
}

TEST_P(AesCtrHmacAeadProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  AesCtrHmacAeadKeyFormat aes_ctr_hmac_aead_key_format =
      BuildAesCtrHmacAeadKeyFormat(
          test_case.aes_key_size, test_case.hmac_key_size, test_case.iv_size,
          test_case.tag_size, test_case.proto_hash_type, /*hmac_version=*/0);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, test_case.output_prefix_type,
          aes_ctr_hmac_aead_key_format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT((*parsed_parameters)->HasIdRequirement(),
              Eq(test_case.id_requirement.has_value()));

  util::StatusOr<AesCtrHmacAeadParameters> expected_parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(test_case.aes_key_size)
          .SetHmacKeySizeInBytes(test_case.hmac_key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());
  EXPECT_THAT(**parsed_parameters, Eq(*expected_parameters));
}

TEST_F(AesCtrHmacAeadProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  AesCtrHmacAeadKeyFormat key_format_proto = BuildAesCtrHmacAeadKeyFormat(
      /*aes_key_size=*/16, /*hmac_key_size=*/16, /*iv_size=*/16,
      /*tag_size=*/16, HashType::SHA256, /*hmac_version=*/0);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseParameters(*serialization)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Failed to parse AesCtrHmacAeadKeyFormat proto")));
}

TEST_F(AesCtrHmacAeadProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefixFails) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  AesCtrHmacAeadKeyFormat key_format_proto = BuildAesCtrHmacAeadKeyFormat(
      /*aes_key_size=*/16, /*hmac_key_size=*/16, /*iv_size=*/16,
      /*tag_size=*/16, HashType::SHA256, /*hmac_version=*/0);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseParameters(*serialization)
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Could not determine AesCtrHmacAeadParameters::Variant")));
}

TEST_F(AesCtrHmacAeadProtoSerializationTest,
       ParseParametersWithUnkownHashTypeFails) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  AesCtrHmacAeadKeyFormat key_format_proto = BuildAesCtrHmacAeadKeyFormat(
      /*aes_key_size=*/16, /*hmac_key_size=*/16, /*iv_size=*/16,
      /*tag_size=*/16, HashType::UNKNOWN_HASH, /*hmac_version=*/0);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseParameters(*serialization)
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Could not determine AesCtrHmacAeadParameters::HashType")));
}

TEST_F(AesCtrHmacAeadProtoSerializationTest,
       ParseParametersWithInvalidHmacVersionFails) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  AesCtrHmacAeadKeyFormat key_format_proto = BuildAesCtrHmacAeadKeyFormat(
      /*aes_key_size=*/16, /*hmac_key_size=*/16, /*iv_size=*/16,
      /*tag_size=*/16, HashType::SHA256, /*hmac_version=*/1);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*serialization)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("only version 0 is accepted")));
}

TEST_P(AesCtrHmacAeadProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(test_case.aes_key_size)
          .SetHmacKeySizeInBytes(test_case.hmac_key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());

  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(test_case.output_prefix_type));

  AesCtrHmacAeadKeyFormat aes_ctr_hmac_aead_key_format;
  ASSERT_THAT(aes_ctr_hmac_aead_key_format.ParseFromString(
                  proto_serialization->GetKeyTemplate().value()),
              IsTrue());
  ASSERT_THAT(aes_ctr_hmac_aead_key_format.aes_ctr_key_format().key_size(),
              Eq(test_case.aes_key_size));
  ASSERT_THAT(
      aes_ctr_hmac_aead_key_format.aes_ctr_key_format().params().iv_size(),
      Eq(test_case.iv_size));
  ASSERT_THAT(aes_ctr_hmac_aead_key_format.hmac_key_format().key_size(),
              Eq(test_case.hmac_key_size));
  ASSERT_THAT(
      aes_ctr_hmac_aead_key_format.hmac_key_format().params().tag_size(),
      Eq(test_case.tag_size));
  ASSERT_THAT(aes_ctr_hmac_aead_key_format.hmac_key_format().params().hash(),
              Eq(test_case.proto_hash_type));
}

TEST_P(AesCtrHmacAeadProtoSerializationTest, ParseKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  std::string aes_key_bytes = Random::GetRandomBytes(test_case.aes_key_size);
  std::string hmac_key_bytes = Random::GetRandomBytes(test_case.hmac_key_size);
  google::crypto::tink::AesCtrHmacAeadKey key_proto = BuildAesCtrHmacAeadKey(
      aes_key_bytes, hmac_key_bytes, test_case.iv_size, test_case.tag_size,
      test_case.proto_hash_type, /*aes_ctr_version=*/0,
      /*hmac_version=*/0);

  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              Eq(test_case.id_requirement.has_value()));

  util::StatusOr<AesCtrHmacAeadParameters> expected_parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(test_case.aes_key_size)
          .SetHmacKeySizeInBytes(test_case.hmac_key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());
  util::StatusOr<AesCtrHmacAeadKey> expected_key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*expected_parameters)
          .SetAesKeyBytes(
              RestrictedData(aes_key_bytes, InsecureSecretKeyAccess::Get()))
          .SetHmacKeyBytes(
              RestrictedData(hmac_key_bytes, InsecureSecretKeyAccess::Get()))
          .SetIdRequirement(test_case.id_requirement)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(AesCtrHmacAeadProtoSerializationTest, ParseLegacyKeyAsCrunchy) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  std::string aes_key_bytes = Random::GetRandomBytes(16);
  std::string hmac_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::AesCtrHmacAeadKey key_proto = BuildAesCtrHmacAeadKey(
      aes_key_bytes, hmac_key_bytes, /*iv_size=*/16, /*tag_size=*/16,
      HashType::SHA256, /*aes_ctr_version=*/0,
      /*hmac_version=*/0);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC,
          OutputPrefixType::LEGACY, /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());

  const AesCtrHmacAeadKey* aes_ctr_hmac_aead_key =
      dynamic_cast<const AesCtrHmacAeadKey*>(key->get());
  ASSERT_THAT(aes_ctr_hmac_aead_key, NotNull());
  EXPECT_THAT(aes_ctr_hmac_aead_key->GetParameters().GetVariant(),
              Eq(AesCtrHmacAeadParameters::Variant::kCrunchy));
}

TEST_F(AesCtrHmacAeadProtoSerializationTest,
       ParseKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse AesCtrHmacAeadKey proto")));
}

TEST_F(AesCtrHmacAeadProtoSerializationTest, ParseKeyNoSecretKeyAccessFails) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  std::string aes_key_bytes = Random::GetRandomBytes(16);
  std::string hmac_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::AesCtrHmacAeadKey key_proto = BuildAesCtrHmacAeadKey(
      aes_key_bytes, hmac_key_bytes, /*iv_size=*/16, /*tag_size=*/16,
      HashType::SHA256, /*aes_ctr_version=*/0,
      /*hmac_version=*/0);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied,
                                     HasSubstr("SecretKeyAccess is required")));
}

TEST_F(AesCtrHmacAeadProtoSerializationTest, ParseKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  std::string aes_key_bytes = Random::GetRandomBytes(16);
  std::string hmac_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::AesCtrHmacAeadKey key_proto = BuildAesCtrHmacAeadKey(
      aes_key_bytes, hmac_key_bytes, /*iv_size=*/16, /*tag_size=*/16,
      HashType::SHA256, /*aes_ctr_version=*/0,
      /*hmac_version=*/0);
  key_proto.set_version(1);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(AesCtrHmacAeadProtoSerializationTest,
       ParseKeyWithInvalidAesCtrKeyVersionFails) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  std::string aes_key_bytes = Random::GetRandomBytes(16);
  std::string hmac_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::AesCtrHmacAeadKey key_proto = BuildAesCtrHmacAeadKey(
      aes_key_bytes, hmac_key_bytes, /*iv_size=*/16, /*tag_size=*/16,
      HashType::SHA256, /*aes_ctr_version=*/1,
      /*hmac_version=*/0);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Only version 0 keys inner AES CTR keys are accepted")));
}

TEST_F(AesCtrHmacAeadProtoSerializationTest,
       ParseKeyWithInvalidHmacKeyVersionFails) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  std::string aes_key_bytes = Random::GetRandomBytes(16);
  std::string hmac_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::AesCtrHmacAeadKey key_proto = BuildAesCtrHmacAeadKey(
      aes_key_bytes, hmac_key_bytes, /*iv_size=*/16, /*tag_size=*/16,
      HashType::SHA256, /*aes_ctr_version=*/0,
      /*hmac_version=*/1);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Only version 0 keys inner HMAC keys are accepted")));
}

TEST_P(AesCtrHmacAeadProtoSerializationTest, SerializeKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  std::string aes_key_bytes = Random::GetRandomBytes(test_case.aes_key_size);
  std::string hmac_key_bytes = Random::GetRandomBytes(test_case.hmac_key_size);
  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(test_case.aes_key_size)
          .SetHmacKeySizeInBytes(test_case.hmac_key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesCtrHmacAeadKey> key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*parameters)
          .SetAesKeyBytes(
              RestrictedData(aes_key_bytes, InsecureSecretKeyAccess::Get()))
          .SetHmacKeyBytes(
              RestrictedData(hmac_key_bytes, InsecureSecretKeyAccess::Get()))
          .SetIdRequirement(test_case.id_requirement)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->KeyMaterialType(), Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(),
              Eq(test_case.id_requirement));

  google::crypto::tink::AesCtrHmacAeadKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.aes_ctr_key().key_value(), Eq(aes_key_bytes));
  EXPECT_THAT(proto_key.aes_ctr_key().params().iv_size(),
              Eq(test_case.iv_size));
  EXPECT_THAT(proto_key.hmac_key().key_value(), Eq(hmac_key_bytes));
  EXPECT_THAT(proto_key.hmac_key().params().tag_size(), Eq(test_case.tag_size));
  EXPECT_THAT(proto_key.hmac_key().params().hash(),
              Eq(test_case.proto_hash_type));
}

TEST_F(AesCtrHmacAeadProtoSerializationTest,
       SerializeKeyNoSecretKeyAccessFails) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  std::string aes_key_bytes = Random::GetRandomBytes(16);
  std::string hmac_key_bytes = Random::GetRandomBytes(16);
  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesCtrHmacAeadKey> key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*parameters)
          .SetAesKeyBytes(
              RestrictedData(aes_key_bytes, InsecureSecretKeyAccess::Get()))
          .SetHmacKeyBytes(
              RestrictedData(hmac_key_bytes, InsecureSecretKeyAccess::Get()))
          .SetIdRequirement(0x23456789)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(*key, absl::nullopt);
  EXPECT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("SecretKeyAccess is required")));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
