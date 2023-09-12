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
#include "tink/util/secret_data.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#else
#include "openssl/ec.h"
#endif
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
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
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.HpkePublicKey";
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
  subtle::EllipticCurveType curve;
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
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5),
                    subtle::EllipticCurveType::NIST_P256},
           TestCase{HpkeParameters::Variant::kCrunchy,
                    HpkeParameters::KemId::kDhkemP384HkdfSha384,
                    HpkeParameters::KdfId::kHkdfSha384,
                    HpkeParameters::AeadId::kAesGcm256,
                    OutputPrefixType::CRUNCHY, HpkeKem::DHKEM_P384_HKDF_SHA384,
                    HpkeKdf::HKDF_SHA384, HpkeAead::AES_256_GCM,
                    /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5),
                    subtle::EllipticCurveType::NIST_P384},
           TestCase{HpkeParameters::Variant::kCrunchy,
                    HpkeParameters::KemId::kDhkemP521HkdfSha512,
                    HpkeParameters::KdfId::kHkdfSha512,
                    HpkeParameters::AeadId::kAesGcm256,
                    OutputPrefixType::CRUNCHY, HpkeKem::DHKEM_P521_HKDF_SHA512,
                    HpkeKdf::HKDF_SHA512, HpkeAead::AES_256_GCM,
                    /*id=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5),
                    subtle::EllipticCurveType::NIST_P521},
           TestCase{HpkeParameters::Variant::kNoPrefix,
                    HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                    HpkeParameters::KdfId::kHkdfSha256,
                    HpkeParameters::AeadId::kChaChaPoly1305,
                    OutputPrefixType::RAW, HpkeKem::DHKEM_X25519_HKDF_SHA256,
                    HpkeKdf::HKDF_SHA256, HpkeAead::CHACHA20_POLY1305,
                    /*id=*/absl::nullopt, /*output_prefix=*/"",
                    subtle::EllipticCurveType::CURVE25519}));

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

struct KeyPair {
  std::string public_key;
  std::string private_key;
};

util::StatusOr<KeyPair> GenerateKeyPair(subtle::EllipticCurveType curve) {
  if (curve == subtle::EllipticCurveType::CURVE25519) {
    util::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
        internal::NewX25519Key();
    if (!x25519_key.ok()) {
      return x25519_key.status();
    }
    return KeyPair{
        std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                    internal::X25519KeyPubKeySize()),
        std::string(reinterpret_cast<const char*>((*x25519_key)->private_key),
                    internal::X25519KeyPrivKeySize())};
  }
  util::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(curve);
  if (!ec_key.ok()) {
    return ec_key.status();
  }
  util::StatusOr<internal::SslUniquePtr<EC_POINT>> ec_point =
      internal::GetEcPoint(curve, ec_key->pub_x, ec_key->pub_y);
  if (!ec_point.ok()) {
    return ec_point.status();
  }
  util::StatusOr<std::string> pub = internal::EcPointEncode(
      curve, subtle::EcPointFormat::UNCOMPRESSED, ec_point->get());
  if (!pub.ok()) {
    return pub.status();
  }
  return KeyPair{*pub, std::string(util::SecretDataAsStringView(ec_key->priv))};
}

TEST_P(HpkeProtoSerializationTest, ParsePublicKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(test_case.kem);
  params.set_kdf(test_case.kdf);
  params.set_aead(test_case.aead);

  util::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.curve);
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::HpkePublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_public_key(key_pair->public_key);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key, KeyData::ASYMMETRIC_PUBLIC,
          test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  util::StatusOr<HpkeParameters> expected_parameters =
      HpkeParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKemId(test_case.kem_id)
          .SetKdfId(test_case.kdf_id)
          .SetAeadId(test_case.aead_id)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<HpkePublicKey> expected_key =
      HpkePublicKey::Create(*expected_parameters, key_pair->public_key,
                            test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(HpkeProtoSerializationTest, ParsePublicKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

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
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParsePublicKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);

  util::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::HpkePublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_public_key(key_pair->public_key);
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
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkeProtoSerializationTest, SerializePublicKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  util::StatusOr<HpkeParameters> parameters = HpkeParameters::Builder()
                                                  .SetVariant(test_case.variant)
                                                  .SetKemId(test_case.kem_id)
                                                  .SetKdfId(test_case.kdf_id)
                                                  .SetAeadId(test_case.aead_id)
                                                  .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.curve);
  ASSERT_THAT(key_pair, IsOk());

  util::StatusOr<HpkePublicKey> key = HpkePublicKey::Create(
      *parameters, key_pair->public_key, test_case.id, GetPartialKeyAccess());
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
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::HpkePublicKey proto_key;
  // OSS proto library complains if input is not converted to a string.
  ASSERT_THAT(proto_key.ParseFromString(std::string(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get()))),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.public_key(), Eq(key_pair->public_key));
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().kem(), Eq(test_case.kem));
  EXPECT_THAT(proto_key.params().kdf(), Eq(test_case.kdf));
  EXPECT_THAT(proto_key.params().aead(), Eq(test_case.aead));
}

TEST_P(HpkeProtoSerializationTest, ParsePrivateKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(test_case.kem);
  params.set_kdf(test_case.kdf);
  params.set_aead(test_case.aead);

  util::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.curve);
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::HpkePublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() = params;
  public_key_proto.set_public_key(key_pair->public_key);

  google::crypto::tink::HpkePrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_private_key(key_pair->private_key);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key, KeyData::ASYMMETRIC_PRIVATE,
          test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  util::StatusOr<HpkeParameters> expected_parameters =
      HpkeParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKemId(test_case.kem_id)
          .SetKdfId(test_case.kdf_id)
          .SetAeadId(test_case.aead_id)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<HpkePublicKey> expected_public_key =
      HpkePublicKey::Create(*expected_parameters, key_pair->public_key,
                            test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  util::StatusOr<HpkePrivateKey> expected_private_key = HpkePrivateKey::Create(
      *expected_public_key,
      RestrictedData(key_pair->private_key, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());

  EXPECT_THAT(**key, Eq(*expected_private_key));
}

TEST_F(HpkeProtoSerializationTest, ParsePrivateKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PRIVATE,
                                              OutputPrefixType::TINK,
                                              /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParsePrivateKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);

  util::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::HpkePublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() = params;
  public_key_proto.set_public_key(key_pair->public_key);

  google::crypto::tink::HpkePrivateKey private_key_proto;
  private_key_proto.set_version(1);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_private_key(key_pair->private_key);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PRIVATE,
                                              OutputPrefixType::TINK,
                                              /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParsePrivateKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);

  util::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::HpkePublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() = params;
  public_key_proto.set_public_key(key_pair->public_key);

  google::crypto::tink::HpkePrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_private_key(key_pair->private_key);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PRIVATE,
                                              OutputPrefixType::TINK,
                                              /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST_P(HpkeProtoSerializationTest, SerializePrivateKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  util::StatusOr<HpkeParameters> parameters = HpkeParameters::Builder()
                                                  .SetVariant(test_case.variant)
                                                  .SetKemId(test_case.kem_id)
                                                  .SetKdfId(test_case.kdf_id)
                                                  .SetAeadId(test_case.aead_id)
                                                  .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.curve);
  ASSERT_THAT(key_pair, IsOk());

  util::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, key_pair->public_key, test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key,
      RestrictedData(key_pair->private_key, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPrivateTypeUrl));
  EXPECT_THAT(proto_serialization->KeyMaterialType(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::HpkePrivateKey proto_key;
  // OSS proto library complains if input is not converted to a string.
  ASSERT_THAT(proto_key.ParseFromString(std::string(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get()))),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.private_key(), Eq(key_pair->private_key));
  EXPECT_THAT(proto_key.has_public_key(), IsTrue());
  EXPECT_THAT(proto_key.public_key().version(), Eq(0));
  EXPECT_THAT(proto_key.public_key().has_params(), IsTrue());
  EXPECT_THAT(proto_key.public_key().params().kem(), Eq(test_case.kem));
  EXPECT_THAT(proto_key.public_key().params().kdf(), Eq(test_case.kdf));
  EXPECT_THAT(proto_key.public_key().params().aead(), Eq(test_case.aead));
  EXPECT_THAT(proto_key.public_key().public_key(), Eq(key_pair->public_key));
}

TEST_F(HpkeProtoSerializationTest, SerializePrivateKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(key_pair, IsOk());

  util::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, key_pair->public_key, /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key,
      RestrictedData(key_pair->private_key, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
