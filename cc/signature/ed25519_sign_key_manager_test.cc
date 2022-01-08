// Copyright 2019 Google Inc.
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

#include "tink/signature/ed25519_sign_key_manager.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "tink/public_key_sign.h"
#include "tink/registry.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#include "tink/subtle/ed25519_verify_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/ed25519.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::Ed25519KeyFormat;
using ::google::crypto::tink::Ed25519PrivateKey;
using ::google::crypto::tink::Ed25519PublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

namespace {

TEST(Ed25519SignKeyManagerTest, Basic) {
  EXPECT_THAT(Ed25519SignKeyManager().get_version(), Eq(0));
  EXPECT_THAT(Ed25519SignKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(Ed25519SignKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"));
}

TEST(Ed25519SignKeyManagerTest, ValidateKeyFormat) {
  EXPECT_THAT(Ed25519SignKeyManager().ValidateKeyFormat(Ed25519KeyFormat()),
              IsOk());
}

TEST(Ed25519SignKeyManagerTest, CreateKey) {
  StatusOr<Ed25519PrivateKey> key_or =
      Ed25519SignKeyManager().CreateKey(Ed25519KeyFormat());
  ASSERT_THAT(key_or.status(), IsOk());
  Ed25519PrivateKey key = key_or.ValueOrDie();

  EXPECT_THAT(key.version(), Eq(0));

  EXPECT_THAT(key.public_key().version(), Eq(key.version()));

  EXPECT_THAT(key.key_value(), SizeIs(32));
  EXPECT_THAT(key.public_key().key_value(), SizeIs(32));
}

TEST(Ed25519SignKeyManagerTest, CreateKeyValid) {
  StatusOr<Ed25519PrivateKey> key_or =
      Ed25519SignKeyManager().CreateKey(Ed25519KeyFormat());
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(Ed25519SignKeyManager().ValidateKey(key_or.ValueOrDie()), IsOk());
}

TEST(Ed25519SignKeyManagerTest, CreateKeyAlwaysNew) {
  absl::flat_hash_set<std::string> keys;
  int num_tests = 100;
  for (int i = 0; i < num_tests; ++i) {
    StatusOr<Ed25519PrivateKey> key_or =
        Ed25519SignKeyManager().CreateKey(Ed25519KeyFormat());
    ASSERT_THAT(key_or.status(), IsOk());
    keys.insert(key_or.ValueOrDie().key_value());
  }
  EXPECT_THAT(keys, SizeIs(num_tests));
}

TEST(Ed25519SignKeyManagerTest, GetPublicKey) {
  StatusOr<Ed25519PrivateKey> key_or =
      Ed25519SignKeyManager().CreateKey(Ed25519KeyFormat());
  ASSERT_THAT(key_or.status(), IsOk());
  StatusOr<Ed25519PublicKey> public_key_or =
      Ed25519SignKeyManager().GetPublicKey(key_or.ValueOrDie());
  ASSERT_THAT(public_key_or.status(), IsOk());
  EXPECT_THAT(public_key_or.ValueOrDie().version(),
              Eq(key_or.ValueOrDie().public_key().version()));
  EXPECT_THAT(public_key_or.ValueOrDie().key_value(),
              Eq(key_or.ValueOrDie().public_key().key_value()));
}

TEST(Ed25519SignKeyManagerTest, Create) {
  StatusOr<Ed25519PrivateKey> key_or =
      Ed25519SignKeyManager().CreateKey(Ed25519KeyFormat());
  ASSERT_THAT(key_or.status(), IsOk());
  Ed25519PrivateKey key = key_or.ValueOrDie();

  auto signer_or =
      Ed25519SignKeyManager().GetPrimitive<PublicKeySign>(key);
  ASSERT_THAT(signer_or.status(), IsOk());

  auto direct_verifier_or =
      subtle::Ed25519VerifyBoringSsl::New(key.public_key().key_value());

  ASSERT_THAT(direct_verifier_or.status(), IsOk());

  std::string message = "Some message";
  EXPECT_THAT(direct_verifier_or.ValueOrDie()->Verify(
                  signer_or.ValueOrDie()->Sign(message).ValueOrDie(), message),
              IsOk());
}

TEST(Ed25519SignKeyManagerTest, CreateDifferentKey) {
  StatusOr<Ed25519PrivateKey> key_or =
      Ed25519SignKeyManager().CreateKey(Ed25519KeyFormat());
  ASSERT_THAT(key_or.status(), IsOk());
  Ed25519PrivateKey key = key_or.ValueOrDie();

  auto signer_or =
      Ed25519SignKeyManager().GetPrimitive<PublicKeySign>(key);
  ASSERT_THAT(signer_or.status(), IsOk());

  auto direct_verifier_or =
      subtle::Ed25519VerifyBoringSsl::New("01234567890123456789012345678901");

  ASSERT_THAT(direct_verifier_or.status(), IsOk());

  std::string message = "Some message";
  EXPECT_THAT(direct_verifier_or.ValueOrDie()->Verify(
                  signer_or.ValueOrDie()->Sign(message).ValueOrDie(), message),
              Not(IsOk()));
}

TEST(Ed25519SignKeyManagerTest, DeriveKey) {
  Ed25519KeyFormat format;

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef0123456789abcdef")};

  StatusOr<Ed25519PrivateKey> key_or =
      Ed25519SignKeyManager().DeriveKey(format, &input_stream);
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(key_or.ValueOrDie().key_value(),
              Eq("0123456789abcdef0123456789abcdef"));
}

TEST(Ed25519SignKeyManagerTest, DeriveKeySignVerify) {
  Ed25519KeyFormat format;

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef0123456789abcdef")};

  Ed25519PrivateKey key =
      Ed25519SignKeyManager().DeriveKey(format, &input_stream).ValueOrDie();
  auto signer_or = Ed25519SignKeyManager().GetPrimitive<PublicKeySign>(key);
  ASSERT_THAT(signer_or.status(), IsOk());

  std::string message = "Some message";
  auto signature = signer_or.ValueOrDie()->Sign(message).ValueOrDie();

  auto verifier_or =
      Ed25519VerifyKeyManager().GetPrimitive<PublicKeyVerify>(key.public_key());

  EXPECT_THAT(verifier_or.ValueOrDie()->Verify(signature, message), IsOk());
}

TEST(Ed25519SignKeyManagerTest, DeriveKeyNotEnoughRandomness) {
  Ed25519KeyFormat format;

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("tooshort")};

  ASSERT_THAT(Ed25519SignKeyManager().DeriveKey(format, &input_stream).status(),
              test::StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace tink
}  // namespace crypto

