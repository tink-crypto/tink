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

#include "walkthrough/write_keyset.h"

#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "walkthrough/load_cleartext_keyset.h"
#include "walkthrough/load_encrypted_keyset.h"
#include "walkthrough/test_util.h"
#include "tink/kms_clients.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace tink_walkthrough {
namespace {

constexpr absl::string_view kSerializedMasterKeyKeyset = R"json({
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
})json";

constexpr absl::string_view kSerializedKeysetToEncrypt = R"json({
  "key": [
    {
      "keyData": {
        "keyMaterialType": "SYMMETRIC",
        "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
        "value": "GhD+9l0RANZjzZEZ8PDp7LRW"
      },
      "keyId": 1931667682,
      "outputPrefixType": "TINK",
      "status": "ENABLED"
    }
  ],
  "primaryKeyId": 1931667682
})json";

using ::crypto::tink::Aead;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::testing::Not;

Status InitFakeKms() {
  static Status* status = new Status([]() {
    Status status = crypto::tink::AeadConfig::Register();
    if (!status.ok()) {
      return status;
    }
    return crypto::tink::KmsClients::Add(
        absl::make_unique<FakeKmsClient>(kSerializedMasterKeyKeyset));
  }());
  return *status;
}

class WriteKeysetTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_THAT(InitFakeKms(), IsOk());
    StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle_to_encrypt =
        LoadKeyset(kSerializedKeysetToEncrypt);
    ASSERT_THAT(keyset_handle_to_encrypt, IsOk());
    keyset_handle_to_encrypt_ = std::move(*keyset_handle_to_encrypt);
  }

  std::unique_ptr<KeysetHandle> keyset_handle_to_encrypt_;
};

TEST_F(WriteKeysetTest, WriteEncryptedKeysetFailsWithNullOutputStream) {
  EXPECT_THAT(WriteEncryptedKeyset(*keyset_handle_to_encrypt_, nullptr,
                                   /*master_kms_key_uri=*/"fake://some_key"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(WriteKeysetTest, WriteEncryptedKeysetFailsWhenStreamFails) {
  auto output_stream = absl::make_unique<std::ostream>(nullptr);
  EXPECT_THAT(
      WriteEncryptedKeyset(*keyset_handle_to_encrypt_, std::move(output_stream),
                           /*master_kms_key_uri=*/"fake://some_key"),
      Not(IsOk()));
}

TEST_F(WriteKeysetTest, WriteEncryptedKeysetFailsNoKmsAvailable) {
  std::stringbuf buffer;
  auto output_stream = absl::make_unique<std::ostream>(&buffer);
  EXPECT_THAT(WriteEncryptedKeyset(
                  *keyset_handle_to_encrypt_, std::move(output_stream),
                  /*master_kms_key_uri=*/"does_not_exist://does_not_exist"),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST_F(WriteKeysetTest, WriteEncryptedKeysetWithValidInputs) {
  std::stringbuf buffer;
  auto output_stream = absl::make_unique<std::ostream>(&buffer);
  constexpr absl::string_view master_kms_key_uri = "fake://some_key";
  ASSERT_THAT(
      WriteEncryptedKeyset(*keyset_handle_to_encrypt_, std::move(output_stream),
                           master_kms_key_uri),
      IsOk());
  StatusOr<std::unique_ptr<Aead>> expected_aead =
      keyset_handle_to_encrypt_->GetPrimitive<Aead>();
  ASSERT_THAT(expected_aead, IsOk());
  constexpr absl::string_view associated_data = "Some associated data";
  constexpr absl::string_view plaintext = "Some plaintext";

  StatusOr<std::string> ciphertext =
      (*expected_aead)->Encrypt(plaintext, associated_data);
  ASSERT_THAT(ciphertext, IsOk());

  // Make sure the encrypted keyset was written correctly by loading it and
  // trying to decrypt ciphertext.
  StatusOr<std::unique_ptr<KeysetHandle>> loaded_keyset =
      LoadKeyset(buffer.str(), master_kms_key_uri);
  ASSERT_THAT(loaded_keyset, IsOk());
  StatusOr<std::unique_ptr<Aead>> loaded_keyset_aead =
      (*loaded_keyset)->GetPrimitive<Aead>();
  ASSERT_THAT(loaded_keyset_aead, IsOk());
  EXPECT_THAT((*loaded_keyset_aead)->Decrypt(*ciphertext, associated_data),
              IsOkAndHolds(plaintext));
}

}  // namespace
}  // namespace tink_walkthrough
