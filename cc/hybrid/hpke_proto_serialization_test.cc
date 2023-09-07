// Copyright 2023 Google LLC
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

#include "tink/hybrid/hpke_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/hpke.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeKeyFormat;
using ::google::crypto::tink::HpkeParams;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.HpkePrivateKey";

struct TestCase {
  HpkeParameters::Variant variant;
  HpkeParameters::KemId kem_id;
  HpkeParameters::KdfId kdf_id;
  HpkeParameters::AeadId aead_id;
  OutputPrefixType output_prefix_type;
  HpkeKem kem;
  HpkeKdf kdf;
  HpkeAead aead;
  absl::optional<int> id;
  std::string output_prefix;
};

class HpkeProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(HpkeProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    HpkeProtoSerializationTestSuite, HpkeProtoSerializationTest,
    Values(TestCase{HpkeParameters::Variant::kTink,
                    HpkeParameters::KemId::kDhkemP256HkdfSha256,
                    HpkeParameters::KdfId::kHkdfSha256,
                    HpkeParameters::AeadId::kAesGcm128, OutputPrefixType::TINK,
                    HpkeKem::DHKEM_P256_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                    HpkeAead::AES_128_GCM, /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{HpkeParameters::Variant::kCrunchy,
                    HpkeParameters::KemId::kDhkemP384HkdfSha384,
                    HpkeParameters::KdfId::kHkdfSha384,
                    HpkeParameters::AeadId::kAesGcm256,
                    OutputPrefixType::CRUNCHY, HpkeKem::DHKEM_P384_HKDF_SHA384,
                    HpkeKdf::HKDF_SHA384, HpkeAead::AES_256_GCM,
                    /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{HpkeParameters::Variant::kCrunchy,
                    HpkeParameters::KemId::kDhkemP521HkdfSha512,
                    HpkeParameters::KdfId::kHkdfSha512,
                    HpkeParameters::AeadId::kAesGcm256,
                    OutputPrefixType::CRUNCHY, HpkeKem::DHKEM_P521_HKDF_SHA512,
                    HpkeKdf::HKDF_SHA512, HpkeAead::AES_256_GCM,
                    /*id=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{HpkeParameters::Variant::kNoPrefix,
                    HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                    HpkeParameters::KdfId::kHkdfSha256,
                    HpkeParameters::AeadId::kChaChaPoly1305,
                    OutputPrefixType::RAW, HpkeKem::DHKEM_X25519_HKDF_SHA256,
                    HpkeKdf::HKDF_SHA256, HpkeAead::CHACHA20_POLY1305,
                    /*id=*/absl::nullopt, /*output_prefix=*/""}));

TEST_P(HpkeProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(test_case.kem);
  params.set_kdf(test_case.kdf);
  params.set_aead(test_case.aead);
  HpkeKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT((*parameters)->HasIdRequirement(), test_case.id.has_value());

  const HpkeParameters* hpke_parameters =
      dynamic_cast<const HpkeParameters*>(parameters->get());
  ASSERT_THAT(hpke_parameters, NotNull());
  EXPECT_THAT(hpke_parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(hpke_parameters->GetKemId(), Eq(test_case.kem_id));
  EXPECT_THAT(hpke_parameters->GetKdfId(), Eq(test_case.kdf_id));
  EXPECT_THAT(hpke_parameters->GetAeadId(), Eq(test_case.aead_id));
}

TEST_F(HpkeProtoSerializationTest, ParseLegacyAsCrunchy) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);
  HpkeKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::LEGACY,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT((*parameters)->HasIdRequirement(), IsTrue());

  const HpkeParameters* hpke_parameters =
      dynamic_cast<const HpkeParameters*>(parameters->get());
  ASSERT_THAT(hpke_parameters, NotNull());
  EXPECT_THAT(hpke_parameters->GetVariant(),
              Eq(HpkeParameters::Variant::kCrunchy));
  EXPECT_THAT(hpke_parameters->GetKemId(),
              Eq(HpkeParameters::KemId::kDhkemX25519HkdfSha256));
  EXPECT_THAT(hpke_parameters->GetKdfId(),
              Eq(HpkeParameters::KdfId::kHkdfSha256));
  EXPECT_THAT(hpke_parameters->GetAeadId(),
              Eq(HpkeParameters::AeadId::kChaChaPoly1305));
}

TEST_F(HpkeProtoSerializationTest, ParseParametersWithInvalidSerialization) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParseParametersWithUnkownOutputPrefix) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);
  HpkeKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParseParametersWithUnkownKem) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::KEM_UNKNOWN);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);
  HpkeKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::TINK,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParseParametersWithUnkownKdf) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::KDF_UNKNOWN);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);
  HpkeKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::TINK,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParseParametersWithUnkownAead) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::AEAD_UNKNOWN);
  HpkeKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::TINK,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkeProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  util::StatusOr<HpkeParameters> parameters = HpkeParameters::Builder()
                                                  .SetVariant(test_case.variant)
                                                  .SetKemId(test_case.kem_id)
                                                  .SetKdfId(test_case.kdf_id)
                                                  .SetAeadId(test_case.aead_id)
                                                  .Build();
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

  HpkeKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  ASSERT_THAT(key_format.has_params(), IsTrue());
  EXPECT_THAT(key_format.params().kem(), Eq(test_case.kem));
  EXPECT_THAT(key_format.params().kdf(), Eq(test_case.kdf));
  EXPECT_THAT(key_format.params().aead(), Eq(test_case.aead));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
