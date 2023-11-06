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
#include "walkthrough/write_cleartext_keyset.h"

#include <memory>
#include <ostream>
#include <sstream>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "walkthrough/load_cleartext_keyset.h"
#include "tink/util/test_matchers.h"

namespace tink_walkthrough {
namespace {

using ::crypto::tink::Aead;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::util::StatusOr;

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

TEST(WriteCleartextKeysetTest, WriteKeysetSerializesCorrectly) {
  ASSERT_THAT(crypto::tink::AeadConfig::Register(), IsOk());
  StatusOr<std::unique_ptr<KeysetHandle>> keyset =
      LoadKeyset(kSerializedKeyset);

  std::stringbuf buffer;
  auto output_stream = absl::make_unique<std::ostream>(&buffer);
  ASSERT_THAT(WriteKeyset(**keyset, std::move(output_stream)), IsOk());

  StatusOr<std::unique_ptr<Aead>> aead =
      (*keyset)->GetPrimitive<crypto::tink::Aead>(
          crypto::tink::ConfigGlobalRegistry());

  // Make sure the encrypted keyset was written correctly by loading it and
  // trying to decrypt ciphertext.
  StatusOr<std::unique_ptr<KeysetHandle>> loaded_keyset =
      LoadKeyset(buffer.str());
  ASSERT_THAT(loaded_keyset, IsOk());
  StatusOr<std::unique_ptr<Aead>> loaded_keyset_aead =
      (*loaded_keyset)
          ->GetPrimitive<crypto::tink::Aead>(
              crypto::tink::ConfigGlobalRegistry());
  ASSERT_THAT(loaded_keyset_aead, IsOk());

  constexpr absl::string_view kPlaintext = "Some plaintext";
  constexpr absl::string_view kAssociatedData = "Some associated data";

  StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(kPlaintext, kAssociatedData);
  EXPECT_THAT((*loaded_keyset_aead)->Decrypt(*ciphertext, kAssociatedData),
              IsOkAndHolds(kPlaintext));
  ciphertext = (*loaded_keyset_aead)->Encrypt(kPlaintext, kAssociatedData);
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, kAssociatedData),
              IsOkAndHolds(kPlaintext));
}

}  // namespace
}  // namespace tink_walkthrough
