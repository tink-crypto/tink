// Copyright 2022 Google LLC
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

#include "walkthrough/load_cleartext_keyset.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/aead/aead_config.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace tink_walkthrough {
namespace {

constexpr absl::string_view kSerializedKeyset = R"string({
  "key": [
    {
      "keyData": {
        "keyMaterialType": "SYMMETRIC",
        "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
        "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
      },
      "keyId": 294406504,
      "outputPrefixType": "TINK",
      "status": "ENABLED"
    }
  ],
  "primaryKeyId": 294406504
})string";

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::StatusOr;

TEST(LoadKeysetTest, LoadKeysetFailsWithInvalidKeyset) {
  EXPECT_THAT(LoadKeyset("Invalid").status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(LoadKeysetTest, LoadKeysetSucceeds) {
  StatusOr<std::unique_ptr<crypto::tink::KeysetHandle>> keyset_handle =
      LoadKeyset(kSerializedKeyset);
  ASSERT_THAT(keyset_handle, IsOk());
  ASSERT_THAT(crypto::tink::AeadConfig::Register(), IsOk());
  // Make sure we can extract the Aead primitive and encrypt/decrypt with it.
  constexpr absl::string_view plaintext = "Some plaintext";
  constexpr absl::string_view associated_data = "Some associated_data";
  StatusOr<std::unique_ptr<crypto::tink::Aead>> aead =
      (*keyset_handle)->GetPrimitive<crypto::tink::Aead>();
  ASSERT_THAT(aead, IsOk());
  StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(plaintext, associated_data);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, associated_data),
              IsOkAndHolds(plaintext));
}

}  // namespace
}  // namespace tink_walkthrough
