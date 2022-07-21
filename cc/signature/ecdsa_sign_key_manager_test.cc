// Copyright 2017 Google LLC
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

#include "tink/signature/ecdsa_sign_key_manager.h"

#include <memory>
#include <sstream>
#include <string>
#include <tuple>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/ssl_util.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/ecdsa.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::Enums;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::EcdsaKeyFormat;
using ::google::crypto::tink::EcdsaParams;
using ::google::crypto::tink::EcdsaPrivateKey;
using ::google::crypto::tink::EcdsaPublicKey;
using ::google::crypto::tink::EcdsaSignatureEncoding;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::Not;
using ::testing::SizeIs;

namespace {

TEST(EcdsaSignKeyManagerTest, Basic) {
  EXPECT_THAT(EcdsaSignKeyManager().get_version(), Eq(0));
  EXPECT_THAT(EcdsaSignKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(EcdsaSignKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"));
}

TEST(EcdsaSignKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKeyFormat(EcdsaKeyFormat()),
              Not(IsOk()));
}

EcdsaKeyFormat CreateValidKeyFormat() {
  EcdsaKeyFormat key_format;
  EcdsaParams* params = key_format.mutable_params();
  params->set_hash_type(HashType::SHA256);
  params->set_curve(EllipticCurveType::NIST_P256);
  params->set_encoding(EcdsaSignatureEncoding::DER);
  return key_format;
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyFormat) {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKeyFormat(format), IsOk());
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyFormatUnknownCurve) {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  EcdsaParams* params = format.mutable_params();
  params->set_curve(EllipticCurveType::UNKNOWN_CURVE);
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKeyFormat(format), Not(IsOk()));
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyFormatBadHashP256) {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  EcdsaParams* params = format.mutable_params();
  params->set_curve(EllipticCurveType::NIST_P256);
  params->set_hash_type(HashType::SHA512);
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKeyFormat(format), Not(IsOk()));
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKeyFormat(format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyFormatBadHashP384) {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  EcdsaParams* params = format.mutable_params();
  params->set_curve(EllipticCurveType::NIST_P384);
  params->set_hash_type(HashType::SHA256);
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKeyFormat(format), Not(IsOk()));
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKeyFormat(format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyFormatBadHashP521) {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  EcdsaParams* params = format.mutable_params();
  params->set_curve(EllipticCurveType::NIST_P521);
  params->set_hash_type(HashType::SHA256);
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKeyFormat(format), Not(IsOk()));
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKeyFormat(format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, CreateKey) {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  StatusOr<EcdsaPrivateKey> key_or = EcdsaSignKeyManager().CreateKey(format);
  ASSERT_THAT(key_or, IsOk());
  EcdsaPrivateKey key = key_or.value();

  EXPECT_THAT(key.version(), Eq(0));

  EXPECT_THAT(key.public_key().version(), Eq(key.version()));
  EXPECT_THAT(key.public_key().params().hash_type(),
              Eq(format.params().hash_type()));
  EXPECT_THAT(key.public_key().params().curve(), Eq(format.params().curve()));
  EXPECT_THAT(key.public_key().params().encoding(),
              Eq(format.params().encoding()));

  EXPECT_THAT(key.public_key().x(), SizeIs(Gt(0)));
  EXPECT_THAT(key.public_key().y(), SizeIs(Gt(0)));

  EXPECT_THAT(key.key_value(), SizeIs(Gt(0)));
}

TEST(EcdsaSignKeyManagerTest, CreateKeyValid) {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  StatusOr<EcdsaPrivateKey> key_or = EcdsaSignKeyManager().CreateKey(format);
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKey(key_or.value()), IsOk());
}

EcdsaPrivateKey CreateValidKey() {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  return EcdsaSignKeyManager().CreateKey(format).value();
}

TEST(EcdsaSignKeyManagerTest, ValidateKey) {
  EcdsaPrivateKey key = CreateValidKey();
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKey(key), IsOk());
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyBadHashP256) {
  EcdsaPrivateKey key = CreateValidKey();
  EcdsaParams* params = key.mutable_public_key()->mutable_params();
  params->set_curve(EllipticCurveType::NIST_P256);
  params->set_hash_type(HashType::SHA512);
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyBadHashP384) {
  EcdsaPrivateKey key = CreateValidKey();
  EcdsaParams* params = key.mutable_public_key()->mutable_params();
  params->set_curve(EllipticCurveType::NIST_P384);
  params->set_hash_type(HashType::SHA256);
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyBadHashP521) {
  EcdsaPrivateKey key = CreateValidKey();
  EcdsaParams* params = key.mutable_public_key()->mutable_params();
  params->set_curve(EllipticCurveType::NIST_P521);
  params->set_hash_type(HashType::SHA256);
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, GetPublicKey) {
  EcdsaPrivateKey key = CreateValidKey();
  StatusOr<EcdsaPublicKey> public_key_or =
      EcdsaSignKeyManager().GetPublicKey(key);

  ASSERT_THAT(public_key_or, IsOk());
  EcdsaPublicKey public_key = public_key_or.value();

  EXPECT_THAT(public_key.version(), Eq(key.public_key().version()));
  EXPECT_THAT(public_key.params().hash_type(),
              Eq(key.public_key().params().hash_type()));
  EXPECT_THAT(public_key.params().curve(),
              Eq(key.public_key().params().curve()));
  EXPECT_THAT(public_key.params().encoding(),
              Eq(key.public_key().params().encoding()));

  EXPECT_THAT(public_key.x(), Eq(key.public_key().x()));
  EXPECT_THAT(public_key.y(), Eq(key.public_key().y()));
}

TEST(EcdsaSignKeyManagerTest, Create) {
  EcdsaPrivateKey private_key = CreateValidKey();
  EcdsaPublicKey public_key =
      EcdsaSignKeyManager().GetPublicKey(private_key).value();

  auto signer_or =
      EcdsaSignKeyManager().GetPrimitive<PublicKeySign>(private_key);
  ASSERT_THAT(signer_or, IsOk());

  internal::EcKey ec_key;
  ec_key.curve = Enums::ProtoToSubtle(public_key.params().curve());
  ec_key.pub_x = public_key.x();
  ec_key.pub_y = public_key.y();
  auto direct_verifier_or = subtle::EcdsaVerifyBoringSsl::New(
      ec_key, Enums::ProtoToSubtle(public_key.params().hash_type()),
      Enums::ProtoToSubtle(public_key.params().encoding()));
  ASSERT_THAT(direct_verifier_or, IsOk());

  std::string message = "Some message";
  EXPECT_THAT(direct_verifier_or.value()->Verify(
                  signer_or.value()->Sign(message).value(), message),
              IsOk());
}

TEST(EcdsaSignKeyManagerTest, CreateDifferentKey) {
  EcdsaPrivateKey private_key = CreateValidKey();
  // Note: we create a new key in the next line.
  EcdsaPublicKey public_key =
      EcdsaSignKeyManager().GetPublicKey(CreateValidKey()).value();

  auto signer_or =
      EcdsaSignKeyManager().GetPrimitive<PublicKeySign>(private_key);
  ASSERT_THAT(signer_or, IsOk());

  internal::EcKey ec_key;
  ec_key.curve = Enums::ProtoToSubtle(public_key.params().curve());
  ec_key.pub_x = public_key.x();
  ec_key.pub_y = public_key.y();
  auto direct_verifier_or = subtle::EcdsaVerifyBoringSsl::New(
      ec_key, Enums::ProtoToSubtle(public_key.params().hash_type()),
      Enums::ProtoToSubtle(public_key.params().encoding()));
  ASSERT_THAT(direct_verifier_or, IsOk());

  std::string message = "Some message";
  EXPECT_THAT(direct_verifier_or.value()->Verify(
                  signer_or.value()->Sign(message).value(), message),
              Not(IsOk()));
}

TEST(EcdsaSignKeyManagerTest, DeriveKeyFailsWithOpenSsl) {
  if (internal::IsBoringSsl()) {
    GTEST_SKIP()
        << "OpenSSL-only test, skipping because Tink is using BoringSSL";
  }
  EcdsaKeyFormat format = CreateValidKeyFormat();
  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef0123456789abcdef")};
  EXPECT_THAT(EcdsaSignKeyManager().DeriveKey(format, &input_stream).status(),
              Not(IsOk()));
}

TEST(EcdsaSignKeyManagerTest, DeriveKeySignVerifySucceedsWithBoringSsl) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP()
        << "Key derivation from an input stream is not supported with OpenSSL";
  }
  EcdsaKeyFormat format = CreateValidKeyFormat();

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef0123456789abcdef")};

  util::StatusOr<EcdsaPrivateKey> key =
      EcdsaSignKeyManager().DeriveKey(format, &input_stream);
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      EcdsaSignKeyManager().GetPrimitive<PublicKeySign>(*key);
  ASSERT_THAT(signer, IsOk());

  constexpr absl::string_view kMessage = "Some message";
  util::StatusOr<std::string> signature = (*signer)->Sign(kMessage);
  ASSERT_THAT(signature, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      EcdsaVerifyKeyManager().GetPrimitive<PublicKeyVerify>(key->public_key());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, kMessage), IsOk());
}

TEST(EcdsaSignKeyManagerTest, DeriveKeyNotEnoughRandomness) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP()
        << "Key derivation from an input stream is not supported with OpenSSL";
  }
  EcdsaKeyFormat format = CreateValidKeyFormat();

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("tooshort")};

  ASSERT_THAT(EcdsaSignKeyManager().DeriveKey(format, &input_stream).status(),
              test::StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, DeriveKeyInvalidCurve) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP()
        << "Key derivation from an input stream is not supported with OpenSSL";
  }
  EcdsaKeyFormat format = CreateValidKeyFormat();
  EcdsaParams* params = format.mutable_params();
  params->set_curve(EllipticCurveType::CURVE25519);

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef0123456789abcdef")};

  ASSERT_THAT(EcdsaSignKeyManager().DeriveKey(format, &input_stream).status(),
              test::StatusIs(absl::StatusCode::kInvalidArgument));
}

// Test vectors have been manually generated based on BoringSSL
// Date: 2021/06/03 commit: 88df13d73d5a74505f046f0bf37fb2fb3e1f1a58
using NistCurveParamsDeriveTest = ::testing::TestWithParam<
    std::tuple<EllipticCurveType, std::string, std::string>>;
INSTANTIATE_TEST_SUITE_P(
    NistCurvesParams, NistCurveParamsDeriveTest,
    ::testing::Values(
        std::make_tuple(
            EllipticCurveType::NIST_P256, "0123456789abcdef0123456789abcdef",
            "ed615ab1a0a8bc0412a02f097e747f33c61c5d1f0c720f3e232213ce4a4b7c38"),
        std::make_tuple(
            EllipticCurveType::NIST_P256, "0000000000000000",
            "19d85dacc6634391175a26a692af2230a1de00860bda799d90e2df6ed8e1e5c6"),
        std::make_tuple(
            EllipticCurveType::NIST_P256, "4242424242424242",
            "055d555a117782553a01a93544ffeced88bc08a50a22138b54c422c4a8cfb3ec"),
        std::make_tuple(EllipticCurveType::NIST_P384,
                        "0123456789abcdef0123456789abcdef",
                        "4c2204d997b64a288ce7c8dbcb9d9543f45c7de458410cd996f28a"
                        "d123e45a146367c2d2100a4336bad949535d1d9e89"),
        std::make_tuple(EllipticCurveType::NIST_P384,
                        "000000000000000000000000",
                        "88d0af7371ae92b3aa2daea3d68d514a5c335ac6c6e5af2a7cf60a"
                        "f71364241d318c022f7846b261c6345bc0c810d816"),
        std::make_tuple(EllipticCurveType::NIST_P384,
                        "424242424242424242424242",
                        "53cfa0a8205c69cd56173a76a99caf19b15bd56ce9a08c6d26067e"
                        "b6b48925bd445cdf213e35b69330e47535ff8f27ad"),
        std::make_tuple(EllipticCurveType::NIST_P521,
                        "0123456789abcdef0123456789abcdef",
                        "014ef526b2a9e965227e83396387a34a441d471f5ab3fe62607e78"
                        "e56619a698ad73bba12e42459e457c08dfa8492daaf8188f72f707"
                        "6b8bc902d4c68729a3330b8f"),
        std::make_tuple(EllipticCurveType::NIST_P521,
                        "00000000000000000000000000000000",
                        "01effa21f65dda9fe6eacd5d4a1865a4117db0ac5617cdaaaae1cf"
                        "f17b261a5fd1804e75e49d8cca288bd3f0a7b77d39bb230c9c5192"
                        "c70e1af9f93403e3705a49d6"),
        std::make_tuple(EllipticCurveType::NIST_P521,
                        "42424242424242424242424242424242",
                        "013fa619e3ea1f71f923b6716619d0044d168637d36e44b828901e"
                        "cef00f6fabcffbd6b5c2c24468a35fed8611aaeeb36b2af7be1eff"
                        "d393151c6b5135a07789f8a4")));

TEST_P(NistCurveParamsDeriveTest, TestVectors) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP()
        << "Key derivation from an input stream is not supported with OpenSSL";
  }
  EcdsaKeyFormat key_format;
  key_format.mutable_params()->set_curve(std::get<0>(GetParam()));

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>(std::get<1>(GetParam()))};

  util::StatusOr<EcdsaPrivateKey> private_key =
      EcdsaSignKeyManager().DeriveKey(key_format, &input_stream);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->key_value(),
              Eq(test::HexDecodeOrDie(std::get<2>(GetParam()))));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
