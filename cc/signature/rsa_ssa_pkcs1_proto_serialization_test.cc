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
#include "tink/signature/rsa_ssa_pkcs1_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/rsa_ssa_pkcs1.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::RsaSsaPkcs1KeyFormat;
using ::google::crypto::tink::RsaSsaPkcs1Params;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  RsaSsaPkcs1Parameters::Variant variant;
  OutputPrefixType output_prefix_type;
  RsaSsaPkcs1Parameters::HashType hash_type;
  HashType proto_hash_type;
  int modulus_size_in_bits;
  absl::optional<int> id;
  std::string output_prefix;
};

const std::string& kF4Str = *new std::string("\x1\0\x1", 3);  // 65537

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey";

class RsaSsaPkcs1ProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(RsaSsaPkcs1ProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPkcs1ProtoSerializationTestSuite, RsaSsaPkcs1ProtoSerializationTest,
    Values(TestCase{RsaSsaPkcs1Parameters::Variant::kTink,
                    OutputPrefixType::TINK,
                    RsaSsaPkcs1Parameters::HashType::kSha256, HashType::SHA256,
                    /*modulus_size=*/2048, /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{RsaSsaPkcs1Parameters::Variant::kCrunchy,
                    OutputPrefixType::CRUNCHY,
                    RsaSsaPkcs1Parameters::HashType::kSha256, HashType::SHA256,
                    /*modulus_size=*/2048, /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{RsaSsaPkcs1Parameters::Variant::kCrunchy,
                    OutputPrefixType::CRUNCHY,
                    RsaSsaPkcs1Parameters::HashType::kSha384, HashType::SHA384,
                    /*modulus_size=*/3072, /*id=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{RsaSsaPkcs1Parameters::Variant::kNoPrefix,
                    OutputPrefixType::RAW,
                    RsaSsaPkcs1Parameters::HashType::kSha512, HashType::SHA512,
                    /*modulus_size=*/3072, /*id=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(RsaSsaPkcs1ProtoSerializationTest, ParseParametersSucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(test_case.modulus_size_in_bits);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.mutable_params()->set_hash_type(test_case.proto_hash_type);

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
  const RsaSsaPkcs1Parameters* rsa_ssa_pkcs1_parameters =
      dynamic_cast<const RsaSsaPkcs1Parameters*>(parameters->get());
  ASSERT_THAT(rsa_ssa_pkcs1_parameters, NotNull());
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetModulusSizeInBits(),
              Eq(test_case.modulus_size_in_bits));
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetHashType(), Eq(test_case.hash_type));
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetPublicExponent(),
              Eq(BigInteger(kF4Str)));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest, ParseParametersLegacyAsCrunchy) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.mutable_params()->set_hash_type(HashType::SHA256);

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

  const RsaSsaPkcs1Parameters* rsa_ssa_pkcs1_parameters =
      dynamic_cast<const RsaSsaPkcs1Parameters*>(parameters->get());

  ASSERT_THAT(rsa_ssa_pkcs1_parameters, NotNull());
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetVariant(),
              Eq(RsaSsaPkcs1Parameters::Variant::kCrunchy));
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetModulusSizeInBits(), Eq(2048));
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetHashType(),
              Eq(RsaSsaPkcs1Parameters::HashType::kSha256));
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetPublicExponent(),
              Eq(BigInteger(kF4Str)));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParseParametersKeyFormatWithoutParamsFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefixFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.mutable_params()->set_hash_type(HashType::SHA256);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest, ParseParametersWithUnkownHashFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.mutable_params()->set_hash_type(HashType::UNKNOWN_HASH);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::TINK,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(RsaSsaPkcs1ProtoSerializationTest, SerializeParametersSucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(test_case.variant)
          .SetHashType(test_case.hash_type)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(kF4Str))
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

  RsaSsaPkcs1KeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());

  ASSERT_THAT(key_format.has_params(), IsTrue());
  EXPECT_THAT(key_format.params().hash_type(), Eq(test_case.proto_hash_type));
  EXPECT_THAT(key_format.modulus_size_in_bits(),
              Eq(test_case.modulus_size_in_bits));
  EXPECT_THAT(key_format.public_exponent(), Eq(kF4Str));
}

struct KeyValues {
  std::string n;
  std::string e;
  std::string p;
  std::string q;
  std::string dp;
  std::string dq;
  std::string d;
  std::string q_inv;
};

KeyValues GenerateKeyValues(int modulus_size_in_bits) {
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  CHECK_NE(rsa.get(), nullptr);

  // Set public exponent to 65537.
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  CHECK_NE(e.get(), nullptr);
  BN_set_word(e.get(), 65537);

  // Generate an RSA key pair and get the values.
  CHECK(RSA_generate_key_ex(rsa.get(), modulus_size_in_bits, e.get(),
                            /*cb=*/nullptr));

  const BIGNUM *n_bn, *e_bn, *d_bn, *p_bn, *q_bn, *dp_bn, *dq_bn, *q_inv_bn;

  RSA_get0_key(rsa.get(), &n_bn, &e_bn, &d_bn);

  util::StatusOr<std::string> n_str =
      internal::BignumToString(n_bn, BN_num_bytes(n_bn));
  CHECK_OK(n_str);
  util::StatusOr<std::string> e_str =
      internal::BignumToString(e_bn, BN_num_bytes(e_bn));
  CHECK_OK(e_str);
  util::StatusOr<std::string> d_str =
      internal::BignumToString(d_bn, BN_num_bytes(d_bn));
  CHECK_OK(d_str);

  RSA_get0_factors(rsa.get(), &p_bn, &q_bn);

  util::StatusOr<std::string> p_str =
      internal::BignumToString(p_bn, BN_num_bytes(p_bn));
  CHECK_OK(p_str);
  util::StatusOr<std::string> q_str =
      internal::BignumToString(q_bn, BN_num_bytes(q_bn));
  CHECK_OK(q_str);

  RSA_get0_crt_params(rsa.get(), &dp_bn, &dq_bn, &q_inv_bn);

  util::StatusOr<std::string> dp_str =
      internal::BignumToString(dp_bn, BN_num_bytes(dp_bn));
  CHECK_OK(dp_str);
  util::StatusOr<std::string> dq_str =
      internal::BignumToString(dq_bn, BN_num_bytes(dq_bn));
  CHECK_OK(dq_str);
  util::StatusOr<std::string> q_inv_str =
      internal::BignumToString(q_inv_bn, BN_num_bytes(q_inv_bn));
  CHECK_OK(q_inv_str);

  return KeyValues{*n_str,  *e_str,  *p_str, *q_str,
                   *dp_str, *dq_str, *d_str, *q_inv_str};
}

TEST_P(RsaSsaPkcs1ProtoSerializationTest, ParsePublicKeySucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1Params params;
  params.set_hash_type(test_case.proto_hash_type);

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  google::crypto::tink::RsaSsaPkcs1PublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
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

  util::StatusOr<RsaSsaPkcs1Parameters> expected_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(test_case.variant)
          .SetHashType(test_case.hash_type)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<RsaSsaPkcs1PublicKey> expected_key =
      RsaSsaPkcs1PublicKey::Create(*expected_parameters,
                                   BigInteger(key_values.n), test_case.id,
                                   GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParsePublicKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

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

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParsePublicKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1Params params;
  params.set_hash_type(HashType::SHA256);

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::RsaSsaPkcs1PublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
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

TEST_P(RsaSsaPkcs1ProtoSerializationTest, SerializePublicKeySucceeds) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  TestCase test_case = GetParam();
  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(test_case.variant)
          .SetHashType(test_case.hash_type)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<RsaSsaPkcs1PublicKey> key =
      RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(key_values.n),
                                   test_case.id, GetPartialKeyAccess());
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

  google::crypto::tink::RsaSsaPkcs1PublicKey proto_key;
  // OSS proto library complains if input is not converted to a string.
  ASSERT_THAT(proto_key.ParseFromString(std::string(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get()))),
              IsTrue());

  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.n(), Eq(key_values.n));
  EXPECT_THAT(proto_key.e(), Eq(key_values.e));
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().hash_type(), Eq(test_case.proto_hash_type));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
