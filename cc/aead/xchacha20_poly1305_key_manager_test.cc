// Copyright 2019 Google LLC
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

#include "tink/aead/xchacha20_poly1305_key_manager.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/aead.h"
#include "tink/subtle/aead_test_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::XChaCha20Poly1305Key;
using ::google::crypto::tink::XChaCha20Poly1305KeyFormat;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::SizeIs;

TEST(XChaCha20Poly1305KeyManagerTest, Basics) {
  EXPECT_THAT(XChaCha20Poly1305KeyManager().get_version(), Eq(0));
  EXPECT_THAT(
      XChaCha20Poly1305KeyManager().get_key_type(),
      Eq("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key"));
  EXPECT_THAT(XChaCha20Poly1305KeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
}

TEST(XChaCha20Poly1305KeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(XChaCha20Poly1305KeyManager().ValidateKey(XChaCha20Poly1305Key()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(XChaCha20Poly1305KeyManagerTest, ValidateValid32ByteKey) {
  XChaCha20Poly1305Key key;
  key.set_version(0);
  key.set_key_value("01234567890123456789012345678901");
  EXPECT_THAT(XChaCha20Poly1305KeyManager().ValidateKey(key), IsOk());
}

TEST(XChaCha20Poly1305KeyManagerTest, ValidateInvalid16ByteKey) {
  XChaCha20Poly1305Key key;
  key.set_version(0);
  key.set_key_value("0123456789012345");
  EXPECT_THAT(XChaCha20Poly1305KeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(XChaCha20Poly1305KeyManagerTest, ValidateInvalid31ByteKey) {
  XChaCha20Poly1305Key key;
  key.set_version(0);
  key.set_key_value("0123456789012345678901234567890");
  EXPECT_THAT(XChaCha20Poly1305KeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(XChaCha20Poly1305KeyManagerTest, ValidateInvalid33ByteKey) {
  XChaCha20Poly1305Key key;
  key.set_version(0);
  key.set_key_value("012345678901234567890123456789012");
  EXPECT_THAT(XChaCha20Poly1305KeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(XChaCha20Poly1305KeyManagerTest, ValidateInvalidVersion) {
  XChaCha20Poly1305Key key;
  key.set_version(1);
  key.set_key_value("01234567890123456789012345678901");
  EXPECT_THAT(XChaCha20Poly1305KeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(XChaCha20Poly1305KeyManagerTest, ValidateKeyFormat) {
  EXPECT_THAT(XChaCha20Poly1305KeyManager().ValidateKeyFormat(
                  XChaCha20Poly1305KeyFormat()),
              IsOk());
}

TEST(XChaCha20Poly1305KeyManagerTest, CreateKey) {
  StatusOr<XChaCha20Poly1305Key> key_or =
      XChaCha20Poly1305KeyManager().CreateKey(XChaCha20Poly1305KeyFormat());

  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(key_or.ValueOrDie().key_value(), SizeIs(32));
  EXPECT_THAT(key_or.ValueOrDie().version(), Eq(0));
}

TEST(XChaCha20Poly1305KeyManagerTest, DeriveKey) {
  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef0123456789abcdef")};
  XChaCha20Poly1305KeyFormat format;
  format.set_version(0);
  StatusOr<XChaCha20Poly1305Key> key_or =
      XChaCha20Poly1305KeyManager().DeriveKey(format, &input_stream);

  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(key_or.ValueOrDie().key_value(), SizeIs(32));
  EXPECT_THAT(key_or.ValueOrDie().version(), Eq(0));
}

TEST(XChaCha20Poly1305KeyManagerTest, DeriveKeyFromLongSeed) {
  util::IstreamInputStream input_stream{absl::make_unique<std::stringstream>(
      "0123456789abcdef0123456789abcdefXXX")};

  XChaCha20Poly1305KeyFormat format;
  format.set_version(0);
  auto key_or = XChaCha20Poly1305KeyManager().DeriveKey(format, &input_stream);

  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(key_or.ValueOrDie().key_value(),
              Eq("0123456789abcdef0123456789abcdef"));
}

TEST(XChaCha20Poly1305KeyManagerTest, DeriveKeyWithoutEnoughEntropy) {
  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0")};
  XChaCha20Poly1305KeyFormat format;
  format.set_version(0);

  StatusOr<XChaCha20Poly1305Key> key_or =
      XChaCha20Poly1305KeyManager().DeriveKey(format, &input_stream);

  ASSERT_THAT(key_or.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                        HasSubstr("pseudorandomness")));
}

TEST(XChaCha20Poly1305KeyManagerTest, DeriveKeyWrongVersion) {
  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef0123456789abcdef")};
  XChaCha20Poly1305KeyFormat format;
  format.set_version(1);
  StatusOr<XChaCha20Poly1305Key> key_or =
      XChaCha20Poly1305KeyManager().DeriveKey(format, &input_stream);

  ASSERT_THAT(key_or.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                        HasSubstr("version")));
}

TEST(XChaCha20Poly1305KeyManagerTest, CreateKeyValid) {
  StatusOr<XChaCha20Poly1305Key> key_or =
      XChaCha20Poly1305KeyManager().CreateKey(XChaCha20Poly1305KeyFormat());

  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(XChaCha20Poly1305KeyManager().ValidateKey(key_or.ValueOrDie()),
              IsOk());
}

TEST(XChaCha20Poly1305KeyManagerTest, CreateAead) {
  StatusOr<XChaCha20Poly1305Key> key_or =
      XChaCha20Poly1305KeyManager().CreateKey(XChaCha20Poly1305KeyFormat());
  ASSERT_THAT(key_or.status(), IsOk());

  StatusOr<std::unique_ptr<Aead>> aead_or =
      XChaCha20Poly1305KeyManager().GetPrimitive<Aead>(key_or.ValueOrDie());

  ASSERT_THAT(aead_or.status(), IsOk());

  StatusOr<std::unique_ptr<Aead>> direct_aead_or =
      subtle::XChacha20Poly1305BoringSsl::New(
          util::SecretDataFromStringView(key_or.ValueOrDie().key_value()));
  ASSERT_THAT(direct_aead_or.status(), IsOk());

  ASSERT_THAT(
      EncryptThenDecrypt(*aead_or.ValueOrDie(),
                         *direct_aead_or.ValueOrDie(), "message", "aad"),
      IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
