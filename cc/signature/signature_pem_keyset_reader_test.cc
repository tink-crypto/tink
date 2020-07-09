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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/signature/signature_config.h"
#include "tink/subtle/pem_parser_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::EqualsKey;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::error::Code;
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

// Helper function that creates an RsaSsaPssPublicKey from the given PEM encoded
// key `pem_encoded_key`, Hash type `hash_type` and key version `key_version`.
RsaSsaPssPublicKey GetRsaSsaPssPublicKeyProto(absl::string_view pem_encoded_key,
                                              HashType hash_type,
                                              uint32_t key_version) {
  auto key_subtle_or = subtle::PemParser::ParseRsaPublicKey(pem_encoded_key);
  std::unique_ptr<subtle::SubtleUtilBoringSSL::RsaPublicKey> key_subtle =
      std::move(key_subtle_or).ValueOrDie();

  RsaSsaPssPublicKey public_key_proto;
  public_key_proto.set_version(key_version);
  public_key_proto.set_e(key_subtle->e);
  public_key_proto.set_n(key_subtle->n);
  public_key_proto.mutable_params()->set_mgf1_hash(hash_type);
  public_key_proto.mutable_params()->set_sig_hash(hash_type);
  public_key_proto.mutable_params()->set_salt_length(
      util::Enums::HashLength(hash_type).ValueOrDie());

  return public_key_proto;
}

// Helper function that creates an RsaSsaPssPrivateKey from the given PEM
// encoded key `pem_encoded_key`, Hash type `hash_type` and key version
// `key_version`.
RsaSsaPssPrivateKey GetRsaSsaPssPrivateKeyProto(
    absl::string_view pem_encoded_key, HashType hash_type,
    uint32_t key_version) {
  // Parse the key with subtle::PemParser to make sure the proto key fields are
  // correct.
  auto key_subtle_or = subtle::PemParser::ParseRsaPrivateKey(pem_encoded_key);
  std::unique_ptr<subtle::SubtleUtilBoringSSL::RsaPrivateKey> key_subtle =
      std::move(key_subtle_or).ValueOrDie();

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
      util::Enums::HashLength(hash_type).ValueOrDie());

  return private_key_proto;
}

// Verify check on PEM array size not zero before creating a reader.
TEST(SignaturePemKeysetReaderTest, BuildEmptyPemArray) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);
  auto keyset_reader_or = builder.Build();
  EXPECT_THAT(keyset_reader_or.status(), StatusIs(Code::INVALID_ARGUMENT));
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
      std::move(keyset_reader_or).ValueOrDie();

  EXPECT_THAT(keyset_reader->ReadEncrypted().status(),
              StatusIs(Code::UNIMPLEMENTED));
}

// Verify parsing works correctly on valid inputs.
TEST(SignaturePemKeysetReaderTest, ReadCorrectPublicKey) {
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
      std::move(keyset_reader_or).ValueOrDie();

  auto keyset_or = keyset_reader->Read();
  ASSERT_THAT(keyset_or.status(), IsOk());
  std::unique_ptr<Keyset> keyset = std::move(keyset_or).ValueOrDie();

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
  expected_keydata1->set_value(
      GetRsaSsaPssPublicKeyProto(kRsaPublicKey2048, HashType::SHA384,
                                 verify_key_manager.get_version())
          .SerializeAsString());
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
  expected_keydata2->set_value(
      GetRsaSsaPssPublicKeyProto(kRsaPublicKey2048, HashType::SHA256,
                                 verify_key_manager.get_version())
          .SerializeAsString());
  EXPECT_THAT(keyset->key(1), EqualsKey(expected_key2));
}

TEST(SignaturePemKeysetReaderTest, ReadCorrectPrivateKey) {
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
      std::move(keyset_reader_or).ValueOrDie();

  auto keyset_or = keyset_reader->Read();
  ASSERT_THAT(keyset_or.status(), IsOk());
  std::unique_ptr<Keyset> keyset = std::move(keyset_or).ValueOrDie();

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
  expected_keydata1->set_value(
      GetRsaSsaPssPrivateKeyProto(kRsaPrivateKey2048, HashType::SHA256,
                                  sign_key_manager.get_version())
          .SerializeAsString());
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
  expected_keydata2->set_value(
      GetRsaSsaPssPrivateKeyProto(kRsaPrivateKey2048, HashType::SHA384,
                                  sign_key_manager.get_version())
          .SerializeAsString());
  EXPECT_THAT(keyset->key(1), EqualsKey(expected_key2));
}

// Expects an INVLID_ARGUMENT when passing a public key to a
// PublicKeySignPemKeysetReader.
TEST(SignaturePemKeysetTeaderTest, ReadRsaPrivateKeyKeyTypeMismatch) {
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
      std::move(keyset_reader_or).ValueOrDie();

  EXPECT_THAT(keyset_reader->Read().status(), StatusIs(Code::INVALID_ARGUMENT));
}

// Expects an INVLID_ARGUMENT when passing a private key to a
// PublicKeyVerifyPemKeysetReader.
TEST(SignaturePemKeysetTeaderTest, ReadRsaPublicKeyKeyTypeMismatch) {
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
      std::move(keyset_reader_or).ValueOrDie();

  EXPECT_THAT(keyset_reader->Read().status(), StatusIs(Code::INVALID_ARGUMENT));
}

// Expects an INVALID_ARGUMENT error as the key size is too small.
TEST(SignaturePemKeysetTeaderTest, ReadRsaPublicKeyTooSmall) {
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
      std::move(keyset_reader_or).ValueOrDie();

  EXPECT_THAT(keyset_reader->Read().status(), StatusIs(Code::INVALID_ARGUMENT));
}

// Expects an INVALID_ARGUMENT error as the key is 2048 bits, but PemKeyParams
// reports 3072.
TEST(SignaturePemKeysetTeaderTest, ReadRsaPublicKeySizeMismatch) {
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
      std::move(keyset_reader_or).ValueOrDie();

  EXPECT_THAT(keyset_reader->Read().status(), StatusIs(Code::INVALID_ARGUMENT));
}

// Expects an INVALID_ARGUMENT error as SHA1 is not allowed.
TEST(SignaturePemKeysetTeaderTest, ReadRsaPublicKeyInvalidHashType) {
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
      std::move(keyset_reader_or).ValueOrDie();

  EXPECT_THAT(keyset_reader->Read().status(), StatusIs(Code::INVALID_ARGUMENT));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
