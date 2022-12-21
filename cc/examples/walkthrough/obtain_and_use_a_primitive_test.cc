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

#include "walkthrough/obtain_and_use_a_primitive.h"

#include <memory>
#include <ostream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "absl/strings/string_view.h"
#include "tink/aead/aead_config.h"
#include "walkthrough/load_cleartext_keyset.h"
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

using ::crypto::tink::KeysetHandle;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::util::StatusOr;

TEST(LoadKeysetTest, EncryptDecrypt) {
  ASSERT_THAT(crypto::tink::AeadConfig::Register(), IsOk());
  StatusOr<std::unique_ptr<KeysetHandle>> master_key_keyset =
      LoadKeyset(kSerializedKeyset);
  ASSERT_THAT(master_key_keyset, IsOk());
  constexpr absl::string_view kPlaintext = "Some data";
  constexpr absl::string_view kAssociatedData = "Some associated data";
  StatusOr<std::string> ciphertext =
      AeadEncrypt(**master_key_keyset, kPlaintext, kAssociatedData);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT(AeadDecrypt(**master_key_keyset, *ciphertext, kAssociatedData),
              IsOkAndHolds(kPlaintext));
}

}  // namespace
}  // namespace tink_walkthrough
