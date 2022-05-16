// Copyright 2018 Google Inc.
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
#include "tink/signature/signature_pem_keyset_reader.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_util.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/signature/signature_config.h"
#include "tink/subtle/pem_parser_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::EqualsKey;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::EcdsaPublicKey;
using ::google::crypto::tink::EcdsaSignatureEncoding;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::RsaSsaPssPrivateKey;
using ::google::crypto::tink::RsaSsaPssPublicKey;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

constexpr absl::string_view kEcdsaP256PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1M5IlCiYLvNDGG65DmoErfQTZjWa\n"
    "UI/nrGayg/BmQa4f9db4zQRCc5IwErn3JtlLDAxQ8fXUoy99klswBEMZ/A==\n"
    "-----END PUBLIC KEY-----\n";
constexpr absl::string_view kEcdsaP256PublicKeyX =
    "d4ce489428982ef343186eb90e6a04adf41366359a508fe7ac66b283f06641ae";
constexpr absl::string_view kEcdsaP256PublicKeyY =
    "1ff5d6f8cd044273923012b9f726d94b0c0c50f1f5d4a32f7d925b30044319fc";

constexpr absl::string_view kEcdsaP384PublicKey =
    "-----BEGIN PUBLIC KEY-----"
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAESbGnhTcoHIGYTgAJLwTCLGEMrCq6ej3p"
    "kr9q0iMF0tVFAYdX7YI8ZDM04Y2VsuZC0qhRRFxdoL8NVD6q1f+YY0SDxUnZYEUk"
    "MSHtbVybpk2rZWptJeAYsBxNOrPxc4mJ"
    "-----END PUBLIC KEY-----";

constexpr absl::string_view kSecp256k1PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEuDj/ROW8F3vyEYnQdmCC/J2EMiaIf8l2\n"
    "A3EQC37iCm/wyddb+6ezGmvKGXRJbutW3jVwcZVdg8Sxutqgshgy6Q==\n"
    "-----END PUBLIC KEY-----";

constexpr absl::string_view kEd25519PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAfU0Of2FTpptiQrUiq77mhf2kQg+INLEIw72uNp71Sfo=\n"
    "-----END PUBLIC KEY-----\n";

constexpr absl::string_view kRsaPublicKey2048 =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsll1i7Arx1tosXYSyb9o\n"
    "xfoFlYozTGHhZ7wgvMdXV8Em6JIQud85iQcs9iYOaIPHzUr00x3emRW2mzAfvvli\n"
    "3oxxvS217GJdollxL4ao3D0kHpaIyCORt78evDWDEfVcJr6RC3b2H+pAjtaS8alX\n"
    "imIsgsD89vae82cOOL/JD2PaTzu70IjIrno8WlXmb2R01WLTLM57ft188BScoOls\n"
    "tlJegfu6gVqPEnSONOUTX1crLhe3ukMAgVl+b7kDPABYhNWTURjGDXWwEPb+zn7N\n"
    "zBy31Y0TiWk9Qzd/Tz3pScseQQXnkrltfwSwzSYqwzz/xaiQ0mdCXmHBnpNjVQ8i\n"
    "hQIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

constexpr absl::string_view kRsaPublicKey1024 =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+lQMh614+1PINuxuGg8ks1DOD\n"
    "pxDGcbLm47clu/J3KE7htWxPaiLsVeowNURyYTLTscZ/AcD7p3ceVDWNwz5xtETI\n"
    "n2GcHy9Jaaph6HSYak2IOg0p5btxqbd9+UfqKhbmrtMNDNrdRJOq8Z7oLlvbzT0x\n"
    "pj37y294RWqIWhm1rwIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

constexpr absl::string_view kRsaPrivateKey2048 =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAsll1i7Arx1tosXYSyb9oxfoFlYozTGHhZ7wgvMdXV8Em6JIQ\n"
    "ud85iQcs9iYOaIPHzUr00x3emRW2mzAfvvli3oxxvS217GJdollxL4ao3D0kHpaI\n"
    "yCORt78evDWDEfVcJr6RC3b2H+pAjtaS8alXimIsgsD89vae82cOOL/JD2PaTzu7\n"
    "0IjIrno8WlXmb2R01WLTLM57ft188BScoOlstlJegfu6gVqPEnSONOUTX1crLhe3\n"
    "ukMAgVl+b7kDPABYhNWTURjGDXWwEPb+zn7NzBy31Y0TiWk9Qzd/Tz3pScseQQXn\n"
    "krltfwSwzSYqwzz/xaiQ0mdCXmHBnpNjVQ8ihQIDAQABAoIBAHYrXf3bEXa6syh6\n"
    "AkLYZzRdz5tggVLHu9C+zrYmIlILsZsBRMHTDM0lCv5hAsTvI9B7LLJBJT8rKt2y\n"
    "SiaAGKk6RxZAljx0hHPQbXU+9N1QSYFW3nQ1VRR5NoUfs6OPfapSM8pz3OoSjQnX\n"
    "VG94c39GQxWzhyifCXxeuQaS1EY0F8g9HKkSdRbvsNVF/2j+rdmWeur8swtYBDCN\n"
    "nBymiDhEBj/Y1Ft3R6ywC14YM/af4aDWTbhQvZYPtITdoEtOWulGkqcx0j/NlMYU\n"
    "SZcaG3M/6UuKXGzibtO4w9LlI00HPlBDi3fQGbezk6WyLNjcE4xj/MKFg7VosgN7\n"
    "XDy68tUCgYEA6FovqDcya6JxivhyVZks98e22sPARwpowI3Nt+gsF5uPcqQMvbot\n"
    "ACzKHjqxRJyGbioMUI8Ao20/f2PxzeI5wAtH2HPNaN6bCbBXvxlCTMCAokbHSWjW\n"
    "stK2PXl2cqF/51ED7EPbgxABetGyfudsx22QowSR66Sq3I8UtZnQVUMCgYEAxIBC\n"
    "EW2oLh9ZUKxEeMuFlMN1FJCCqIx3zeVjUtAC3Vm/VvodEL0KM7w9Y123BfeoWMnG\n"
    "HaqNUEZRUO/bMvaiIXVykF19NTCxym4s6eKNBwGsdWvxroRm0k37uhflt9A7iVX6\n"
    "HmDVPYgjLJbPmLc8+Ms5ML6Od7qXKajRFOPmSJcCgYEA28JY6s/x9013+InNkdpD\n"
    "ZsNU1gpo9IgK1XwJQ1TrRxTRkwtIJbZN06mJLRg0C4HDv7QzW4o1f1zXvsQnsqOy\n"
    "HUpOFJJKiFJq7roD8/GO/Irh3xn0aSEoV4/l37Te68KF96FvhWoU1xwvWhu1qEN4\n"
    "ZhLhxt2OqgJfvCXz32LwYYMCgYBVEL0JNHJw/Qs6PEksDdcXLoI509FsS9r1XE9i\n"
    "I0CKOHb3nTEF9QA8o0nkAUbhI3RSc477esDQNpCvPBalelV3rJNa4c35P8pHuuhg\n"
    "m723gcb50i/+/7xPYIkP55Z/u3p6mqi7i+nkSFIJ1IOsNe8EOV3ZtzSPqkwUMcvJ\n"
    "gltHowKBgQDkB76QzH3xb4jABKehkCxVxqyGLKxU7SOZpLpCc/5OHbo12u/CwlwG\n"
    "uAeidKZk3SJEmj0F1+Aiir2KRv+RX543VvzCtEXNkVViVrirzvjZUGKPdkMWfbF8\n"
    "OdD7qHPPNu5jSyaroeN6VqfbELpewhYzulMEipckEZlU4+Dxu2k1eQ==\n"
    "-----END RSA PRIVATE KEY-----\n";

// Helper function that creates an EcdsaPublicKey from the given PEM encoded
// key `pem_encoded_key`, Hash type `hash_type` and key version `key_version`.
EcdsaPublicKey GetExpectedEcdsaPublicKeyProto(EcdsaSignatureEncoding encoding) {
  EcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_x(absl::HexStringToBytes(kEcdsaP256PublicKeyX));
  public_key_proto.set_y(absl::HexStringToBytes(kEcdsaP256PublicKeyY));
  public_key_proto.mutable_params()->set_hash_type(HashType::SHA256);
  public_key_proto.mutable_params()->set_curve(EllipticCurveType::NIST_P256);
  public_key_proto.mutable_params()->set_encoding(encoding);

  return public_key_proto;
}

// Helper function that creates an RsaSsaPssPublicKey from the given PEM encoded
// key `pem_encoded_key`, Hash type `hash_type` and key version `key_version`.
util::StatusOr<RsaSsaPssPublicKey> GetRsaSsaPssPublicKeyProto(
    absl::string_view pem_encoded_key, HashType hash_type,
    uint32_t key_version) {
  util::StatusOr<std::unique_ptr<internal::RsaPublicKey>> public_key =
      subtle::PemParser::ParseRsaPublicKey(pem_encoded_key);
  if (!public_key.ok()) {
    return public_key.status();
  }
  std::unique_ptr<internal::RsaPublicKey> key_subtle = *std::move(public_key);

  RsaSsaPssPublicKey public_key_proto;
  public_key_proto.set_version(key_version);
  public_key_proto.set_e(key_subtle->e);
  public_key_proto.set_n(key_subtle->n);
  public_key_proto.mutable_params()->set_mgf1_hash(hash_type);
  public_key_proto.mutable_params()->set_sig_hash(hash_type);
  public_key_proto.mutable_params()->set_salt_length(
      util::Enums::HashLength(hash_type).value());

  return public_key_proto;
}

// Helper function that creates an RsaSsaPssPrivateKey from the given PEM
// encoded key `pem_encoded_key`, Hash type `hash_type` and key version
// `key_version`.
util::StatusOr<RsaSsaPssPrivateKey> GetRsaSsaPssPrivateKeyProto(
    absl::string_view pem_encoded_key, HashType hash_type,
    uint32_t key_version) {
  // Parse the key with subtle::PemParser to make sure the proto key fields are
  // correct.
  util::StatusOr<std::unique_ptr<internal::RsaPrivateKey>> private_key =
      subtle::PemParser::ParseRsaPrivateKey(pem_encoded_key);
  if (!private_key.ok()) {
    return private_key.status();
  }
  std::unique_ptr<internal::RsaPrivateKey> key_subtle = *std::move(private_key);

  // Set the inner RSASSA-PSS public key and its parameters.
  RsaSsaPssPrivateKey private_key_proto;

  private_key_proto.set_version(key_version);
  private_key_proto.set_d(
      std::string(util::SecretDataAsStringView(key_subtle->d)));
  private_key_proto.set_p(
      std::string(util::SecretDataAsStringView(key_subtle->p)));
  private_key_proto.set_q(
      std::string(util::SecretDataAsStringView(key_subtle->q)));
  private_key_proto.set_dp(
      std::string(util::SecretDataAsStringView(key_subtle->dp)));
  private_key_proto.set_dq(
      std::string(util::SecretDataAsStringView(key_subtle->dq)));
  private_key_proto.set_crt(
      std::string(util::SecretDataAsStringView(key_subtle->crt)));

  // Set public key parameters.
  RsaSsaPssPublicKey* public_key_proto = private_key_proto.mutable_public_key();
  public_key_proto->set_version(key_version);
  public_key_proto->set_e(key_subtle->e);
  public_key_proto->set_n(key_subtle->n);
  // Set algorithm-specific parameters.
  public_key_proto->mutable_params()->set_mgf1_hash(hash_type);
  public_key_proto->mutable_params()->set_sig_hash(hash_type);
  public_key_proto->mutable_params()->set_salt_length(
      util::Enums::HashLength(hash_type).value());

  return private_key_proto;
}

// Verify check on PEM array size not zero before creating a reader.
TEST(SignaturePemKeysetReaderTest, BuildEmptyPemArray) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);
  auto keyset_reader_or = builder.Build();
  EXPECT_THAT(keyset_reader_or.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Make sure ReadUnencrypted returns an UNSUPPORTED error as expected.
TEST(SignaturePemKeysetReaderTest, ReadEncryptedUnsupported) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  builder.Add({.serialized_key = std::string(kRsaPublicKey2048),
               .parameters = {.key_type = PemKeyType::PEM_RSA,
                              .algorithm = PemAlgorithm::RSASSA_PSS,
                              .key_size_in_bits = 2048,
                              .hash_type = HashType::SHA384}});

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or.status(), IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  EXPECT_THAT(keyset_reader->ReadEncrypted().status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}

// Verify parsing works correctly on valid inputs.
TEST(SignaturePemKeysetReaderTest, ReadRsaCorrectPublicKey) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add({.serialized_key = std::string(kRsaPublicKey2048),
               .parameters = {.key_type = PemKeyType::PEM_RSA,
                              .algorithm = PemAlgorithm::RSASSA_PSS,
                              .key_size_in_bits = 2048,
                              .hash_type = HashType::SHA384}});
  builder.Add({.serialized_key = std::string(kRsaPublicKey2048),
               .parameters = {.key_type = PemKeyType::PEM_RSA,
                              .algorithm = PemAlgorithm::RSASSA_PSS,
                              .key_size_in_bits = 2048,
                              .hash_type = HashType::SHA256}});

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or.status(), IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  auto keyset_or = keyset_reader->Read();
  ASSERT_THAT(keyset_or.status(), IsOk());
  std::unique_ptr<Keyset> keyset = std::move(keyset_or).value();

  // Key manager to validate key type and key material type.
  RsaSsaPssVerifyKeyManager verify_key_manager;
  EXPECT_THAT(keyset->key(), SizeIs(2));
  EXPECT_EQ(keyset->primary_key_id(), keyset->key(0).key_id());
  EXPECT_THAT(keyset->key(0).key_id(), Not(Eq(keyset->key(1).key_id())));

  // Build the expectedi primary key.
  Keyset::Key expected_key1;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_key1.set_key_id(keyset->primary_key_id());
  expected_key1.set_status(KeyStatusType::ENABLED);
  expected_key1.set_output_prefix_type(OutputPrefixType::RAW);
  // Populate the expected primary key KeyData.
  KeyData* expected_keydata1 = expected_key1.mutable_key_data();
  expected_keydata1->set_type_url(verify_key_manager.get_key_type());
  expected_keydata1->set_key_material_type(
      verify_key_manager.key_material_type());

  util::StatusOr<RsaSsaPssPublicKey> rsa_ssa_pss_pub_key =
      GetRsaSsaPssPublicKeyProto(kRsaPublicKey2048, HashType::SHA384,
                                 verify_key_manager.get_version());
  ASSERT_THAT(rsa_ssa_pss_pub_key.status(), IsOk());
  expected_keydata1->set_value(rsa_ssa_pss_pub_key->SerializeAsString());
  EXPECT_THAT(keyset->key(0), EqualsKey(expected_key1));

  // Build the expected second key.
  Keyset::Key expected_key2;
  // ID is randomly generated, so we simply copy the secondary key ID.
  expected_key2.set_key_id(keyset->key(1).key_id());
  expected_key2.set_status(KeyStatusType::ENABLED);
  expected_key2.set_output_prefix_type(OutputPrefixType::RAW);
  // Populate the expected second key KeyData.
  KeyData* expected_keydata2 = expected_key2.mutable_key_data();
  expected_keydata2->set_type_url(verify_key_manager.get_key_type());
  expected_keydata2->set_key_material_type(
      verify_key_manager.key_material_type());

  util::StatusOr<RsaSsaPssPublicKey> rsa_ssa_pss_pub_key2 =
      GetRsaSsaPssPublicKeyProto(kRsaPublicKey2048, HashType::SHA256,
                                 verify_key_manager.get_version());
  ASSERT_THAT(rsa_ssa_pss_pub_key2.status(), IsOk());
  expected_keydata2->set_value(rsa_ssa_pss_pub_key2->SerializeAsString());

  EXPECT_THAT(keyset->key(1), EqualsKey(expected_key2));
}

TEST(SignaturePemKeysetReaderTest, ReadRsaCorrectPrivateKey) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);

  builder.Add({.serialized_key = std::string(kRsaPrivateKey2048),
               .parameters = {.key_type = PemKeyType::PEM_RSA,
                              .algorithm = PemAlgorithm::RSASSA_PSS,
                              .key_size_in_bits = 2048,
                              .hash_type = HashType::SHA256}});
  builder.Add({.serialized_key = std::string(kRsaPrivateKey2048),
               .parameters = {.key_type = PemKeyType::PEM_RSA,
                              .algorithm = PemAlgorithm::RSASSA_PSS,
                              .key_size_in_bits = 2048,
                              .hash_type = HashType::SHA384}});

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or.status(), IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  auto keyset_or = keyset_reader->Read();
  ASSERT_THAT(keyset_or.status(), IsOk());
  std::unique_ptr<Keyset> keyset = std::move(keyset_or).value();

  EXPECT_THAT(keyset->key(), SizeIs(2));
  EXPECT_EQ(keyset->primary_key_id(), keyset->key(0).key_id());
  EXPECT_THAT(keyset->key(0).key_id(), Not(Eq(keyset->key(1).key_id())));

  // Key manager to validate key type and key material type.
  RsaSsaPssSignKeyManager sign_key_manager;

  // Build the expected primary key.
  Keyset::Key expected_key1;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_key1.set_key_id(keyset->primary_key_id());
  expected_key1.set_status(KeyStatusType::ENABLED);
  expected_key1.set_output_prefix_type(OutputPrefixType::RAW);
  // Populate the expected primary key KeyData.
  KeyData* expected_keydata1 = expected_key1.mutable_key_data();
  expected_keydata1->set_type_url(sign_key_manager.get_key_type());
  expected_keydata1->set_key_material_type(
      sign_key_manager.key_material_type());
  util::StatusOr<RsaSsaPssPrivateKey> rsa_pss_private_key1 =
      GetRsaSsaPssPrivateKeyProto(kRsaPrivateKey2048, HashType::SHA256,
                                  sign_key_manager.get_version());
  ASSERT_THAT(rsa_pss_private_key1.status(), IsOk());
  expected_keydata1->set_value(rsa_pss_private_key1->SerializeAsString());
  EXPECT_THAT(keyset->key(0), EqualsKey(expected_key1));

  // Build the expected second key.
  Keyset::Key expected_key2;
  // ID is randomly generated, so we simply copy the one from the second key.
  expected_key2.set_key_id(keyset->key(1).key_id());
  expected_key2.set_status(KeyStatusType::ENABLED);
  expected_key2.set_output_prefix_type(OutputPrefixType::RAW);
  // Populate the expected second key KeyData.
  KeyData* expected_keydata2 = expected_key2.mutable_key_data();
  expected_keydata2->set_type_url(sign_key_manager.get_key_type());
  expected_keydata2->set_key_material_type(
      sign_key_manager.key_material_type());
  util::StatusOr<RsaSsaPssPrivateKey> rsa_pss_private_key2 =
      GetRsaSsaPssPrivateKeyProto(kRsaPrivateKey2048, HashType::SHA384,
                                  sign_key_manager.get_version());
  ASSERT_THAT(rsa_pss_private_key2.status(), IsOk());
  expected_keydata2->set_value(rsa_pss_private_key2->SerializeAsString());
  EXPECT_THAT(keyset->key(1), EqualsKey(expected_key2));
}

// Expects an INVLID_ARGUMENT when passing a public key to a
// PublicKeySignPemKeysetReader.
TEST(SignaturePemKeysetReaderTest, ReadRsaPrivateKeyKeyTypeMismatch) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);
  builder.Add({.serialized_key = std::string(kRsaPublicKey2048),
               .parameters = {.key_type = PemKeyType::PEM_RSA,
                              .algorithm = PemAlgorithm::RSASSA_PSS,
                              .key_size_in_bits = 2048,
                              .hash_type = HashType::SHA384}});

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or.status(), IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  EXPECT_THAT(keyset_reader->Read().status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Expects an INVLID_ARGUMENT when passing a private key to a
// PublicKeyVerifyPemKeysetReader.
TEST(SignaturePemKeysetReaderTest, ReadRsaPublicKeyKeyTypeMismatch) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add({.serialized_key = std::string(kRsaPrivateKey2048),
               .parameters = {.key_type = PemKeyType::PEM_RSA,
                              .algorithm = PemAlgorithm::RSASSA_PSS,
                              .key_size_in_bits = 2048,
                              .hash_type = HashType::SHA256}});

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or.status(), IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  EXPECT_THAT(keyset_reader->Read().status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Expects an INVALID_ARGUMENT error as the key size is too small.
TEST(SignaturePemKeysetReaderTest, ReadRsaPublicKeyTooSmall) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add({.serialized_key = std::string(kRsaPublicKey1024),
               .parameters = {.key_type = PemKeyType::PEM_RSA,
                              .algorithm = PemAlgorithm::RSASSA_PSS,
                              .key_size_in_bits = 1024,
                              .hash_type = HashType::SHA256}});

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or.status(), IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  EXPECT_THAT(keyset_reader->Read().status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Expects an INVALID_ARGUMENT error as the key is 2048 bits, but PemKeyParams
// reports 3072.
TEST(SignaturePemKeysetReaderTest, ReadRsaPublicKeySizeMismatch) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add({.serialized_key = std::string(kRsaPublicKey2048),
               .parameters = {.key_type = PemKeyType::PEM_RSA,
                              .algorithm = PemAlgorithm::RSASSA_PSS,
                              .key_size_in_bits = 3072,
                              .hash_type = HashType::SHA256}});

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or.status(), IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  EXPECT_THAT(keyset_reader->Read().status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Expects an INVALID_ARGUMENT error as SHA1 is not allowed.
TEST(SignaturePemKeysetReaderTest, ReadRsaPublicKeyInvalidHashType) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add({.serialized_key = std::string(kRsaPublicKey2048),
               .parameters = {.key_type = PemKeyType::PEM_RSA,
                              .algorithm = PemAlgorithm::RSASSA_PSS,
                              .key_size_in_bits = 2048,
                              .hash_type = HashType::SHA1}});

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or.status(), IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  EXPECT_THAT(keyset_reader->Read().status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignaturePemKeysetReaderTest, ReadECDSACorrectPublicKey) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add({.serialized_key = std::string(kEcdsaP256PublicKey),
               .parameters = {.key_type = PemKeyType::PEM_EC,
                              .algorithm = PemAlgorithm::ECDSA_IEEE,
                              .key_size_in_bits = 256,
                              .hash_type = HashType::SHA256}});

  builder.Add({.serialized_key = std::string(kEcdsaP256PublicKey),
               .parameters = {.key_type = PemKeyType::PEM_EC,
                              .algorithm = PemAlgorithm::ECDSA_DER,
                              .key_size_in_bits = 256,
                              .hash_type = HashType::SHA256}});

  auto reader = builder.Build();
  ASSERT_THAT(reader.status(), IsOk());

  auto keyset_read = reader->get()->Read();
  ASSERT_THAT(keyset_read.status(), IsOk());
  std::unique_ptr<Keyset> keyset = std::move(keyset_read).value();

  // Key manager to validate key type and key material type.
  EcdsaVerifyKeyManager key_manager;
  EXPECT_THAT(keyset->key(), SizeIs(2));
  EXPECT_THAT(keyset->primary_key_id(), keyset->key(0).key_id());
  EXPECT_THAT(keyset->key(0).key_id(), Not(Eq(keyset->key(1).key_id())));

  // Build the expected primary key.
  Keyset::Key expected_primary;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_primary.set_key_id(keyset->primary_key_id());
  expected_primary.set_status(KeyStatusType::ENABLED);
  expected_primary.set_output_prefix_type(OutputPrefixType::RAW);

  // Populate the expected primary key KeyData.
  KeyData* expected_primary_data = expected_primary.mutable_key_data();
  expected_primary_data->set_type_url(key_manager.get_key_type());
  expected_primary_data->set_key_material_type(key_manager.key_material_type());
  expected_primary_data->set_value(
      GetExpectedEcdsaPublicKeyProto(
          EcdsaSignatureEncoding::IEEE_P1363).SerializeAsString());
  EXPECT_THAT(keyset->key(0), EqualsKey(expected_primary))
      << "expected key: " << expected_primary.DebugString();

  // Build the expected secondary key.
  Keyset::Key expected_secondary;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_secondary.set_key_id(keyset->key(1).key_id());
  expected_secondary.set_status(KeyStatusType::ENABLED);
  expected_secondary.set_output_prefix_type(OutputPrefixType::RAW);

  // Populate the expected secondary key KeyData.
  KeyData* expected_secondary_data = expected_secondary.mutable_key_data();
  expected_secondary_data->set_type_url(key_manager.get_key_type());
  expected_secondary_data->set_key_material_type(
      key_manager.key_material_type());
  expected_secondary_data->set_value(
      GetExpectedEcdsaPublicKeyProto(
          EcdsaSignatureEncoding::DER).SerializeAsString());
  EXPECT_THAT(keyset->key(1), EqualsKey(expected_secondary))
      << "expected key: " << expected_secondary.DebugString();
}

TEST(SignaturePemKeysetReaderTest, ReadECDSAWrongHashType) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add({.serialized_key = std::string(kEcdsaP256PublicKey),
               .parameters = {.key_type = PemKeyType::PEM_EC,
                              .algorithm = PemAlgorithm::ECDSA_IEEE,
                              .key_size_in_bits = 256,
                              .hash_type = HashType::SHA512}});

  auto reader = builder.Build();
  ASSERT_THAT(reader.status(), IsOk());
  auto keyset_read = reader->get()->Read();
  ASSERT_THAT(keyset_read.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignaturePemKeysetReaderTest, ReadECDSAWrongKeySize) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add({.serialized_key = std::string(kEcdsaP256PublicKey),
               .parameters = {.key_type = PemKeyType::PEM_EC,
                              .algorithm = PemAlgorithm::ECDSA_IEEE,
                              .key_size_in_bits = 512,
                              .hash_type = HashType::SHA256}});

  auto reader = builder.Build();
  ASSERT_THAT(reader.status(), IsOk());
  auto keyset_read = reader->get()->Read();
  ASSERT_THAT(keyset_read.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignaturePemKeysetReaderTest, ReadECDSAWrongAlgorithm) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add({.serialized_key = std::string(kEcdsaP256PublicKey),
               .parameters = {.key_type = PemKeyType::PEM_EC,
                              .algorithm = PemAlgorithm::RSASSA_PSS,
                              .key_size_in_bits = 256,
                              .hash_type = HashType::SHA256}});

  auto reader = builder.Build();
  ASSERT_THAT(reader.status(), IsOk());
  auto keyset_read = reader->get()->Read();
  ASSERT_THAT(keyset_read.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignaturePemKeysetReaderTest, ReadEd25519ShouldFail) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add({.serialized_key = std::string(kEd25519PublicKey),
               .parameters = {.key_type = PemKeyType::PEM_EC,
                              .algorithm = PemAlgorithm::ECDSA_IEEE,
                              .key_size_in_bits = 256,
                              .hash_type = HashType::SHA256}});

  auto reader = builder.Build();
  ASSERT_THAT(reader.status(), IsOk());
  auto keyset_read = reader->get()->Read();
  ASSERT_THAT(keyset_read.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignaturePemKeysetReaderTest, ReadSecp256k1ShouldFail) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add({.serialized_key = std::string(kSecp256k1PublicKey),
               .parameters = {.key_type = PemKeyType::PEM_EC,
                              .algorithm = PemAlgorithm::ECDSA_IEEE,
                              .key_size_in_bits = 256,
                              .hash_type = HashType::SHA256}});

  auto reader = builder.Build();
  ASSERT_THAT(reader.status(), IsOk());
  auto keyset_read = reader->get()->Read();
  // With BoringSSL parsing of the PEM key fails when an unsupported curve is
  // used [1]; Supported curves are defined here [2]. Tink doesn't distinguish
  // between an error caused by a malformed PEM and an unsupported group by
  // BoringSSL. On the other hand, with OpenSSL parsing succeeds, but this
  // curve is unsupported by Tink. As a consequence, this fails with two
  // different errors.
  //
  // [1]https://github.com/google/boringssl/blob/master/crypto/ec_extra/ec_asn1.c#L324
  // [2]https://github.com/google/boringssl/blob/master/crypto/fipsmodule/ec/ec.c#L218
  if (internal::IsBoringSsl()) {
    EXPECT_THAT(keyset_read.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  } else {
    EXPECT_THAT(keyset_read.status(),
                StatusIs(absl::StatusCode::kUnimplemented));
  }
}

TEST(SignaturePemKeysetReaderTest, ReadEcdsaP384ShouldFail) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add({.serialized_key = std::string(kEcdsaP384PublicKey),
               .parameters = {.key_type = PemKeyType::PEM_EC,
                              .algorithm = PemAlgorithm::ECDSA_IEEE,
                              .key_size_in_bits = 384,
                              .hash_type = HashType::SHA384}});

  auto reader = builder.Build();
  ASSERT_THAT(reader.status(), IsOk());
  auto keyset_read = reader->get()->Read();
  ASSERT_THAT(keyset_read.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
