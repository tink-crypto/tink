// Copyright 2021 Google LLC
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

#include "tink/hybrid/hpke_config.h"

#include <list>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/config/tink_fips.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid/hybrid_key_templates.h"
#include "tink/hybrid/internal/hpke_private_key_manager.h"
#include "tink/hybrid/internal/hpke_public_key_manager.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/keyset_handle.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
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
using ::google::crypto::tink::HpkeParams;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;

class HpkeConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(HpkeConfigTest, Basic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::get_key_manager<HybridDecrypt>(
                  internal::HpkePrivateKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(Registry::get_key_manager<HybridEncrypt>(
                  internal::HpkePublicKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(RegisterHpke(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<HybridDecrypt>(
                  internal::HpkePrivateKeyManager().get_key_type())
                  .status(),
              IsOk());
  EXPECT_THAT(Registry::get_key_manager<HybridEncrypt>(
                  internal::HpkePublicKeyManager().get_key_type())
                  .status(),
              IsOk());
}

TEST_F(HpkeConfigTest, HpkeProtoParamsSerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              HybridKeyTemplates::HpkeX25519HkdfSha256Aes256Gcm());
  ASSERT_THAT(proto_params_serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parsed_params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params.status(), StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialized_params =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params.status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(RegisterHpke(), IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parsed_params2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params2, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialized_params2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params2, IsOk());
}

TEST_F(HpkeConfigTest, HpkeProtoPublicKeySerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  const std::string raw_key = subtle::Random::GetRandomBytes(32);

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::AES_256_GCM);
  google::crypto::tink::HpkePublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_public_key(raw_key);
  *key_proto.mutable_params() = params;

  util::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.HpkePublicKey",
          RestrictedData(key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyData::ASYMMETRIC_PUBLIC, OutputPrefixType::TINK,
          /*id_requirement=*/123);
  ASSERT_THAT(proto_key_serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HpkePublicKey> key = HpkePublicKey::Create(
      *parameters, raw_key, /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(RegisterHpke(), IsOk());

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

TEST_F(HpkeConfigTest, HpkeProtoPrivateKeySerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<std::unique_ptr<internal::X25519Key>> key_pair =
      internal::NewX25519Key();
  ASSERT_THAT(key_pair, IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::AES_256_GCM);
  google::crypto::tink::HpkePublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_public_key(
      std::string(reinterpret_cast<const char*>((*key_pair)->public_value),
                  internal::X25519KeyPubKeySize()));
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::HpkePrivateKey private_key_proto;
  private_key_proto.set_version(0);
  private_key_proto.set_private_key(
      std::string(reinterpret_cast<const char*>((*key_pair)->private_key),
                  internal::X25519KeyPrivKeySize()));
  *private_key_proto.mutable_public_key() = public_key_proto;

  util::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
          RestrictedData(private_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyData::ASYMMETRIC_PRIVATE, OutputPrefixType::TINK,
          /*id_requirement=*/123);
  ASSERT_THAT(proto_key_serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters,
      std::string(reinterpret_cast<const char*>((*key_pair)->public_value),
                  internal::X25519KeyPubKeySize()),
      /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_bytes = RestrictedData(
      std::string(reinterpret_cast<const char*>((*key_pair)->private_key),
                  internal::X25519KeyPrivKeySize()),
      InsecureSecretKeyAccess::Get());

  util::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(RegisterHpke(), IsOk());

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
TEST_F(HpkeConfigTest, RegisterNonFipsTemplates) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  EXPECT_THAT(RegisterHpke(), IsOk());

  // Check that we can not retrieve non-FIPS keyset handle
  std::list<google::crypto::tink::KeyTemplate> non_fips_key_templates;
  non_fips_key_templates.push_back(
      HybridKeyTemplates::HpkeX25519HkdfSha256Aes128Gcm());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::HpkeX25519HkdfSha256Aes256Gcm());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::HpkeX25519HkdfSha256ChaCha20Poly1305());

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
