// Copyright 2020 Google LLC
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

#include "tink/daead/subtle/aead_or_daead.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::StatusOr;

// Checks whether Decrypt(Encrypt(message)) == message with the given
// aead_or_daead.
crypto::tink::util::Status EncryptThenDecrypt(
    const AeadOrDaead& aead_or_daead, absl::string_view message,
    absl::string_view associated_data) {
  StatusOr<std::string> encryption_or =
      aead_or_daead.Encrypt(message, associated_data);
  if (!encryption_or.status().ok()) return encryption_or.status();
  StatusOr<std::string> decryption_or =
      aead_or_daead.Decrypt(encryption_or.value(), associated_data);
  if (!decryption_or.status().ok()) return decryption_or.status();
  if (decryption_or.value() != message) {
    return crypto::tink::util::Status(absl::StatusCode::kInternal,
                                      "Message/Decryption mismatch");
  }
  return util::OkStatus();
}

TEST(AeadOrDaead, testWithAeadPrimitive) {
  std::unique_ptr<Aead> aead = absl::make_unique<test::DummyAead>("TestAead");
  AeadOrDaead aead_or_daead(std::move(aead));

  EXPECT_THAT(EncryptThenDecrypt(aead_or_daead, "test_plaintext", "aad"),
              IsOk());
}

TEST(AeadOrDaead, testWithDeterministicAeadPrimitive) {
  std::unique_ptr<DeterministicAead> daead =
      absl::make_unique<test::DummyDeterministicAead>("TestDaead");
  AeadOrDaead aead_or_daead(std::move(daead));

  EXPECT_THAT(EncryptThenDecrypt(aead_or_daead, "test_plaintext", "aad"),
              IsOk());
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
