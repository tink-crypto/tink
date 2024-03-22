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

#include "tink/hybrid/hybrid_config.h"

#include <list>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "tink/config/global_registry.h"
#include "tink/crypto_format.h"
#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_private_key.h"
#include "tink/hybrid/ecies_public_key.h"
#include "tink/hybrid/hybrid_key_templates.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
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
#include "tink/primitive_set.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm.pb.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyHybridDecrypt;
using ::crypto::tink::test::DummyHybridEncrypt;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::EciesAeadDemParams;
using ::google::crypto::tink::EciesAeadHkdfParams;
using ::google::crypto::tink::EciesAeadHkdfPrivateKey;
using ::google::crypto::tink::EciesAeadHkdfPublicKey;
using ::google::crypto::tink::EciesHkdfKemParams;
using ::google::crypto::tink::EcPointFormat;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;

class HybridConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(HybridConfigTest, Basic) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::get_key_manager<HybridDecrypt>(
                  EciesAeadHkdfPrivateKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(Registry::get_key_manager<HybridEncrypt>(
                  EciesAeadHkdfPublicKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(HybridConfig::Register(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<HybridDecrypt>(
                  EciesAeadHkdfPrivateKeyManager().get_key_type())
                  .status(),
              IsOk());
  EXPECT_THAT(Registry::get_key_manager<HybridEncrypt>(
                  EciesAeadHkdfPublicKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// Tests that the HybridEncryptWrapper has been properly registered and we
// can wrap primitives.
TEST_F(HybridConfigTest, EncryptWrapperRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_TRUE(HybridConfig::Register().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<HybridEncrypt>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyHybridEncrypt>("dummy"),
                             key_info)
              .value()),
      IsOk());

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(wrapped.ok()) << wrapped.status();
  auto encryption_result = wrapped.value()->Encrypt("secret", "");
  ASSERT_TRUE(encryption_result.ok());

  std::string prefix = CryptoFormat::GetOutputPrefix(key_info).value();
  EXPECT_EQ(
      encryption_result.value(),
      absl::StrCat(prefix,
                   DummyHybridEncrypt("dummy").Encrypt("secret", "").value()));
}

// Tests that the HybridDecryptWrapper has been properly registered and we
// can wrap primitives.
TEST_F(HybridConfigTest, DecryptWrapperRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_TRUE(HybridConfig::Register().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<HybridDecrypt>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyHybridDecrypt>("dummy"),
                             key_info)
              .value()),
      IsOk());

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(wrapped.ok()) << wrapped.status();

  std::string prefix = CryptoFormat::GetOutputPrefix(key_info).value();
  std::string encryption =
      DummyHybridEncrypt("dummy").Encrypt("secret", "").value();

  ASSERT_EQ(
      wrapped.value()->Decrypt(absl::StrCat(prefix, encryption), "").value(),
      "secret");
}

TEST_F(HybridConfigTest, EciesProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes256Gcm());
  ASSERT_THAT(proto_params_serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parsed_params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params.status(), StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256GcmRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialized_params =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params.status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(HybridConfig::Register(), IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parsed_params2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params2, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialized_params2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params2, IsOk());
}

EciesAeadHkdfParams CreateParams() {
  EciesHkdfKemParams kem_params;
  kem_params.set_curve_type(EllipticCurveType::CURVE25519);
  kem_params.set_hkdf_hash_type(HashType::SHA256);

  EciesAeadDemParams dem_params;
  AesGcmKeyFormat format;
  format.set_key_size(32);
  format.set_version(0);
  KeyTemplate key_template;
  key_template.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  format.SerializeToString(key_template.mutable_value());
  *dem_params.mutable_aead_dem() = key_template;

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() = kem_params;
  *params.mutable_dem_params() = dem_params;
  params.set_ec_point_format(EcPointFormat::COMPRESSED);

  return params;
}

TEST_F(HybridConfigTest, EciesProtoPublicKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  const std::string public_key_bytes =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());

  EciesAeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_x(public_key_bytes);
  *public_key_proto.mutable_params() = CreateParams();

  util::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
          RestrictedData(public_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyData::ASYMMETRIC_PUBLIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*parameters, public_key_bytes,
                                           /*id_requirement=*/absl::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *public_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(HybridConfig::Register(), IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key2, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialized_key2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *public_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key2, IsOk());
}

TEST_F(HybridConfigTest, EciesProtoPrivateKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  const std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  const std::string private_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->private_key),
                  internal::X25519KeyPrivKeySize());

  EciesAeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_x(public_key_bytes);
  *public_key_proto.mutable_params() = CreateParams();

  EciesAeadHkdfPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(private_key_bytes);

  util::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
          RestrictedData(private_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyData::ASYMMETRIC_PRIVATE, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*parameters, public_key_bytes,
                                           /*id_requirement=*/absl::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(
          *public_key,
          RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(HybridConfig::Register(), IsOk());

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

// FIPS-only mode tests
TEST_F(HybridConfigTest, RegisterNonFipsTemplates) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode with BoringCrypto";
  }

  EXPECT_THAT(HybridConfig::Register(), IsOk());

  // Check that we can not retrieve non-FIPS keyset handle
  std::list<google::crypto::tink::KeyTemplate> non_fips_key_templates;
  non_fips_key_templates.push_back(
      HybridKeyTemplates::
          EciesP256CompressedHkdfHmacSha256Aes128CtrHmacSha256());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::EciesP256CompressedHkdfHmacSha256Aes128Gcm());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128CtrHmacSha256());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::
          EciesP256HkdfHmacSha256Aes128GcmCompressedWithoutPrefix());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes128CtrHmacSha256());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes128Gcm());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::EciesX25519HkdfHmacSha256XChaCha20Poly1305());

  for (auto key_template : non_fips_key_templates) {
    EXPECT_THAT(
        KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry())
            .status(),
        StatusIs(absl::StatusCode::kNotFound));
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
