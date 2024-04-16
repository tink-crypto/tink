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
///////////////////////////////////////////////////////////////////////////////

#include "tink/experimental/pqcrypto/signature/slh_dsa_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_parameters.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_public_key.h"
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
#include "proto/experimental/pqcrypto/slh_dsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::SlhDsaHashType;
using ::google::crypto::tink::SlhDsaKeyFormat;
using ::google::crypto::tink::SlhDsaParams;
using ::google::crypto::tink::SlhDsaSignatureType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.SlhDsaPublicKey";

struct TestCase {
  SlhDsaParameters::Variant variant;
  OutputPrefixType output_prefix_type;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

class SlhDsaProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  SlhDsaProtoSerializationTest() {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(SlhDsaProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    SlhDsaProtoSerializationTestSuite, SlhDsaProtoSerializationTest,
    Values(TestCase{SlhDsaParameters::Variant::kTink, OutputPrefixType::TINK,
                    0x02030400, std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{SlhDsaParameters::Variant::kTink, OutputPrefixType::TINK,
                    0x03050709, std::string("\x01\x03\x05\x07\x09", 5)},
           TestCase{SlhDsaParameters::Variant::kNoPrefix, OutputPrefixType::RAW,
                    absl::nullopt, ""}));

TEST_P(SlhDsaProtoSerializationTest,
       ParseSlhDsa128Sha2SmallSignatureParametersWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  SlhDsaKeyFormat key_format_proto;
  SlhDsaParams& params = *key_format_proto.mutable_params();
  params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
  params.set_hash_type(SlhDsaHashType::SHA2);
  params.set_key_size(64);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_EQ((*parameters)->HasIdRequirement(),
            test_case.id_requirement.has_value());

  const SlhDsaParameters* slh_dsa_parameters =
      dynamic_cast<const SlhDsaParameters*>(parameters->get());
  ASSERT_THAT(slh_dsa_parameters, NotNull());
  EXPECT_THAT(slh_dsa_parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(slh_dsa_parameters->GetPrivateKeySizeInBytes(), Eq(64));
  EXPECT_THAT(slh_dsa_parameters->GetSignatureType(),
              Eq(SlhDsaParameters::SignatureType::kSmallSignature));
  EXPECT_THAT(slh_dsa_parameters->GetHashType(),
              Eq(SlhDsaParameters::HashType::kSha2));
}

TEST_F(SlhDsaProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*serialization)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse SlhDsaKeyFormat proto")));
}

TEST_F(SlhDsaProtoSerializationTest, ParseParametersWithInvalidVersionFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  SlhDsaKeyFormat key_format_proto;
  key_format_proto.set_version(1);
  SlhDsaParams& params = *key_format_proto.mutable_params();
  params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
  params.set_hash_type(SlhDsaHashType::SHA2);
  params.set_key_size(64);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(SlhDsaProtoSerializationTest,
       ParseParametersKeyFormatWithoutParamsFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  SlhDsaKeyFormat key_format_proto;
  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("SlhDsaKeyFormat proto is missing params")));
}

TEST_F(SlhDsaProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefixFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  SlhDsaKeyFormat key_format_proto;
  SlhDsaParams& params = *key_format_proto.mutable_params();
  params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
  params.set_hash_type(SlhDsaHashType::SHA2);
  params.set_key_size(64);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine SlhDsaParameters::Variant")));
}

TEST_F(SlhDsaProtoSerializationTest, ParseParametersWithUnkownSigTypeFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  SlhDsaKeyFormat key_format_proto;
  SlhDsaParams& params = *key_format_proto.mutable_params();
  params.set_sig_type(SlhDsaSignatureType::SLH_DSA_SIGNATURE_TYPE_UNSPECIFIED);
  params.set_hash_type(SlhDsaHashType::SHA2);
  params.set_key_size(64);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      parameters.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Could not determine SlhDsaParameters::SignatureType")));
}

TEST_F(SlhDsaProtoSerializationTest, ParseParametersWithUnkownHashTypeFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  SlhDsaKeyFormat key_format_proto;
  SlhDsaParams& params = *key_format_proto.mutable_params();
  params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
  params.set_hash_type(SlhDsaHashType::SLH_DSA_HASH_TYPE_UNSPECIFIED);
  params.set_key_size(64);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine SlhDsaParameters::HashType")));
}

TEST_P(SlhDsaProtoSerializationTest,
       SerializeSlhDsa128Sha2SmallSignatureParametersWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  util::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(),
              Eq(kPrivateTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(test_case.output_prefix_type));

  SlhDsaKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  ASSERT_TRUE(key_format.has_params());
  EXPECT_THAT(key_format.params().hash_type(), Eq(SlhDsaHashType::SHA2));
  EXPECT_THAT(key_format.params().sig_type(),
              Eq(SlhDsaSignatureType::SMALL_SIGNATURE));
  EXPECT_THAT(key_format.params().key_size(), Eq(64));
}

TEST_P(SlhDsaProtoSerializationTest, ParsePublicKeyWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  SlhDsaParams params;
  params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
  params.set_hash_type(SlhDsaHashType::SHA2);
  params.set_key_size(64);

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::SlhDsaPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key, KeyData::ASYMMETRIC_PUBLIC,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id_requirement.has_value());

  util::StatusOr<SlhDsaParameters> expected_parameters =
      SlhDsaParameters::Create(
          SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
          SlhDsaParameters::SignatureType::kSmallSignature, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<SlhDsaPublicKey> expected_key =
      SlhDsaPublicKey::Create(*expected_parameters, raw_key_bytes,
                              test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(SlhDsaProtoSerializationTest,
       ParsePublicKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PUBLIC,
                                              OutputPrefixType::TINK,
                                              /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse SlhDsaPublicKey proto")));
}

TEST_F(SlhDsaProtoSerializationTest, ParsePublicKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  SlhDsaParams params;
  params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
  params.set_hash_type(SlhDsaHashType::SHA2);
  params.set_key_size(64);

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::SlhDsaPublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_key_value(raw_key_bytes);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PUBLIC,
                                              OutputPrefixType::TINK,
                                              /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_P(SlhDsaProtoSerializationTest, SerializePublicKeyWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  util::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  util::StatusOr<SlhDsaPublicKey> key =
      SlhDsaPublicKey::Create(*parameters, raw_key_bytes,
                              test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPublicTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPublicTypeUrl));
  EXPECT_THAT(proto_serialization->KeyMaterialType(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(),
              Eq(test_case.id_requirement));

  google::crypto::tink::SlhDsaPublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(raw_key_bytes));
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().key_size(), Eq(64));
  EXPECT_THAT(proto_key.params().hash_type(), Eq(SlhDsaHashType::SHA2));
  EXPECT_THAT(proto_key.params().sig_type(),
              Eq(SlhDsaSignatureType::SMALL_SIGNATURE));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
