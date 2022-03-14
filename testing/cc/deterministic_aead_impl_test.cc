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

#include "deterministic_aead_impl.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/daead/deterministic_aead_config.h"
#include "tink/daead/deterministic_aead_key_templates.h"
#include "proto/testing/testing_api.grpc.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::DeterministicAeadKeyTemplates;

using ::testing::Eq;
using ::testing::IsEmpty;
using ::tink_testing_api::DeterministicAeadDecryptRequest;
using ::tink_testing_api::DeterministicAeadDecryptResponse;
using ::tink_testing_api::DeterministicAeadEncryptRequest;
using ::tink_testing_api::DeterministicAeadEncryptResponse;

using crypto::tink::KeysetHandle;
using google::crypto::tink::KeyTemplate;

std::string ValidKeyset() {
  const KeyTemplate& key_template = DeterministicAeadKeyTemplates::Aes256Siv();
  auto handle_result = KeysetHandle::GenerateNew(key_template);
  EXPECT_TRUE(handle_result.ok());
  std::stringbuf keyset;
  auto writer_result =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset));
  EXPECT_TRUE(writer_result.ok());

  auto status = CleartextKeysetHandle::Write(writer_result.ValueOrDie().get(),
                                             *handle_result.ValueOrDie());
  EXPECT_TRUE(status.ok());
  return keyset.str();
}

class DeterministicAeadImplTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    ASSERT_TRUE(DeterministicAeadConfig::Register().ok());
  }
};

TEST_F(DeterministicAeadImplTest, EncryptDecryptSuccess) {
  tink_testing_api::DeterministicAeadImpl daead;
  std::string keyset = ValidKeyset();
  DeterministicAeadEncryptRequest enc_request;
  enc_request.set_keyset(keyset);
  enc_request.set_plaintext("Plain text");
  enc_request.set_associated_data("ad");
  DeterministicAeadEncryptResponse enc_response;

  EXPECT_TRUE(
      daead.EncryptDeterministically(nullptr, &enc_request, &enc_response)
          .ok());
  EXPECT_THAT(enc_response.err(), IsEmpty());

  DeterministicAeadDecryptRequest dec_request;
  dec_request.set_keyset(keyset);
  dec_request.set_ciphertext(enc_response.ciphertext());
  dec_request.set_associated_data("ad");
  DeterministicAeadDecryptResponse dec_response;

  EXPECT_TRUE(
      daead.DecryptDeterministically(nullptr, &dec_request, &dec_response)
          .ok());
  EXPECT_THAT(dec_response.err(), IsEmpty());
  EXPECT_THAT(dec_response.plaintext(), Eq("Plain text"));
}

TEST_F(DeterministicAeadImplTest, EncryptBadKeysetFail) {
  tink_testing_api::DeterministicAeadImpl daead;
  DeterministicAeadEncryptRequest enc_request;
  enc_request.set_keyset("bad keyset");
  enc_request.set_plaintext("Plain text");
  enc_request.set_associated_data("ad");
  DeterministicAeadEncryptResponse enc_response;

  EXPECT_TRUE(
      daead.EncryptDeterministically(nullptr, &enc_request, &enc_response)
          .ok());
  EXPECT_THAT(enc_response.err(), Not(IsEmpty()));
}

TEST_F(DeterministicAeadImplTest, DecryptBadCiphertextFail) {
  tink_testing_api::DeterministicAeadImpl daead;
  std::string keyset = ValidKeyset();
  DeterministicAeadDecryptRequest dec_request;
  dec_request.set_keyset(keyset);
  dec_request.set_ciphertext("bad ciphertext");
  dec_request.set_associated_data("ad");
  DeterministicAeadDecryptResponse dec_response;

  EXPECT_TRUE(
      daead.DecryptDeterministically(nullptr, &dec_request, &dec_response)
          .ok());
  EXPECT_THAT(dec_response.err(), Not(IsEmpty()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
