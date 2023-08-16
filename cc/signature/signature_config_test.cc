// Copyright 2017 Google Inc.
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

#include "tink/signature/signature_config.h"

#include <list>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "openssl/crypto.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/keyset_handle.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/subtle/random.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/ed25519.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyPublicKeySign;
using ::crypto::tink::test::DummyPublicKeyVerify;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Not;

class SignatureConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(SignatureConfigTest, testBasic) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  EXPECT_THAT(Registry::get_key_manager<PublicKeySign>(
                  RsaSsaPssSignKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(Registry::get_key_manager<PublicKeyVerify>(
                  RsaSsaPssVerifyKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(SignatureConfig::Register(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<PublicKeySign>(
                  RsaSsaPssSignKeyManager().get_key_type())
                  .status(),
              IsOk());
  EXPECT_THAT(Registry::get_key_manager<PublicKeyVerify>(
                  RsaSsaPssVerifyKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// Tests that the PublicKeySignWrapper has been properly registered and we
// can wrap primitives.
TEST_F(SignatureConfigTest, PublicKeySignWrapperRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(SignatureConfig::Register().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<PublicKeySign>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyPublicKeySign>("dummy"),
                             key_info)
              .value()),
      IsOk());

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(wrapped.ok()) << wrapped.status();
  auto signature_result = wrapped.value()->Sign("message");
  ASSERT_TRUE(signature_result.ok());

  std::string prefix = CryptoFormat::GetOutputPrefix(key_info).value();
  EXPECT_EQ(signature_result.value(),
            absl::StrCat(prefix,
                         DummyPublicKeySign("dummy").Sign("message").value()));
}


// Tests that the PublicKeyVerifyWrapper has been properly registered and we
// can wrap primitives.
TEST_F(SignatureConfigTest, PublicKeyVerifyWrapperRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(SignatureConfig::Register().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<PublicKeyVerify>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyPublicKeyVerify>("dummy"),
                             key_info)
              .value()),
      IsOk());
  std::string prefix = CryptoFormat::GetOutputPrefix(key_info).value();
  std::string signature = DummyPublicKeySign("dummy").Sign("message").value();

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(wrapped.ok()) << wrapped.status();
  ASSERT_TRUE(
      wrapped.value()->Verify(absl::StrCat(prefix, signature), "message").ok());
}

// FIPS-only mode tests
TEST_F(SignatureConfigTest, RegisterNonFipsTemplates) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode with BoringCrypto.";
  }

  EXPECT_THAT(SignatureConfig::Register(), IsOk());

  std::list<google::crypto::tink::KeyTemplate> non_fips_key_templates;
  non_fips_key_templates.push_back(SignatureKeyTemplates::Ed25519());
  non_fips_key_templates.push_back(
      SignatureKeyTemplates::Ed25519WithRawOutput());
  // 4096-bit RSA is not validated.
  non_fips_key_templates.push_back(
      SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4());
  non_fips_key_templates.push_back(
      SignatureKeyTemplates::RsaSsaPss4096Sha384Sha384F4());
  non_fips_key_templates.push_back(
      SignatureKeyTemplates::RsaSsaPss4096Sha512Sha512F4());

  for (auto key_template : non_fips_key_templates) {
    EXPECT_THAT(KeysetHandle::GenerateNew(key_template).status(),
                Not(IsOk()));
  }
}

TEST_F(SignatureConfigTest, RegisterFipsValidTemplates) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode with BoringCrypto.";
  }

  EXPECT_THAT(SignatureConfig::Register(), IsOk());

  std::list<google::crypto::tink::KeyTemplate> fips_key_templates;
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP256());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP256Ieee());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP384Sha384());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP384Sha512());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP384Ieee());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP521());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP521Ieee());
  fips_key_templates.push_back(
      SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4());
  fips_key_templates.push_back(
      SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4());

  for (auto key_template : fips_key_templates) {
    EXPECT_THAT(KeysetHandle::GenerateNew(key_template), IsOk());
  }
}

TEST_F(SignatureConfigTest, Ed25519ProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              SignatureKeyTemplates::Ed25519());
  ASSERT_THAT(proto_params_serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parsed_params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params.status(), StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialized_params =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params.status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parsed_params2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params2, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialized_params2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params2, IsOk());
}

TEST_F(SignatureConfigTest, Ed25519ProtoPublicKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  const std::string raw_key = subtle::Random::GetRandomBytes(32);

  google::crypto::tink::Ed25519PublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key);

  util::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.Ed25519PublicKey",
          RestrictedData(key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyData::ASYMMETRIC_PUBLIC, OutputPrefixType::TINK,
          /*id_requirement=*/123);
  ASSERT_THAT(proto_key_serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<Ed25519PublicKey> key =
      Ed25519PublicKey::Create(*params, raw_key,
                               /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key2, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialized_key2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key2, IsOk());
}

TEST_F(SignatureConfigTest, Ed25519ProtoPrivateKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::Ed25519PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_key_value((*key_pair)->public_key);

  google::crypto::tink::Ed25519PrivateKey private_key_proto;
  private_key_proto.set_version(0);
  private_key_proto.set_key_value((*key_pair)->private_key);
  *private_key_proto.mutable_public_key() = public_key_proto;

  util::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
          RestrictedData(private_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyData::ASYMMETRIC_PRIVATE, OutputPrefixType::TINK,
          /*id_requirement=*/123);
  ASSERT_THAT(proto_key_serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<Ed25519PublicKey> public_key =
      Ed25519PublicKey::Create(*params, (*key_pair)->public_key,
                               /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_bytes =
      RestrictedData((*key_pair)->private_key, InsecureSecretKeyAccess::Get());

  util::StatusOr<Ed25519PrivateKey> private_key = Ed25519PrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key2, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialized_key2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key2, IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
