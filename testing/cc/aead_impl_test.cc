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

#include "aead_impl.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "proto/testing/testing_api.grpc.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::AeadKeyTemplates;
using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;

using ::testing::Eq;
using ::testing::IsEmpty;
using ::tink_testing_api::AeadDecryptRequest;
using ::tink_testing_api::AeadEncryptRequest;
using ::tink_testing_api::AeadEncryptResponse;
using ::tink_testing_api::AeadDecryptResponse;

using crypto::tink::KeysetHandle;
using google::crypto::tink::KeyTemplate;

std::string ValidKeyset() {
  const KeyTemplate& key_template = AeadKeyTemplates::Aes128Eax();
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

class AeadImplTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() { ASSERT_TRUE(AeadConfig::Register().ok()); }
};

TEST_F(AeadImplTest, EncryptDecryptSuccess) {
  tink_testing_api::AeadImpl aead;
  std::string keyset = ValidKeyset();
  AeadEncryptRequest enc_request;
  enc_request.set_keyset(keyset);
  enc_request.set_plaintext("Plain text");
  enc_request.set_associated_data("ad");
  AeadEncryptResponse enc_response;

  EXPECT_TRUE(aead.Encrypt(nullptr, &enc_request, &enc_response).ok());
  EXPECT_THAT(enc_response.err(), IsEmpty());

  AeadDecryptRequest dec_request;
  dec_request.set_keyset(keyset);
  dec_request.set_ciphertext(enc_response.ciphertext());
  dec_request.set_associated_data("ad");
  AeadDecryptResponse dec_response;

  EXPECT_TRUE(aead.Decrypt(nullptr, &dec_request, &dec_response).ok());
  EXPECT_THAT(dec_response.err(), IsEmpty());
  EXPECT_THAT(dec_response.plaintext(), Eq("Plain text"));
}

TEST_F(AeadImplTest, EncryptBadKeysetFail) {
  tink_testing_api::AeadImpl aead;
  AeadEncryptRequest enc_request;
  enc_request.set_keyset("bad keyset");
  enc_request.set_plaintext("Plain text");
  enc_request.set_associated_data("ad");
  AeadEncryptResponse enc_response;

  EXPECT_TRUE(aead.Encrypt(nullptr, &enc_request, &enc_response).ok());
  EXPECT_THAT(enc_response.err(), Not(IsEmpty()));
}

TEST_F(AeadImplTest, DecryptBadCiphertextFail) {
  tink_testing_api::AeadImpl aead;
  std::string keyset = ValidKeyset();
  AeadDecryptRequest dec_request;
  dec_request.set_keyset(keyset);
  dec_request.set_ciphertext("bad ciphertext");
  dec_request.set_associated_data("ad");
  AeadDecryptResponse dec_response;

  EXPECT_TRUE(aead.Decrypt(nullptr, &dec_request, &dec_response).ok());
  EXPECT_THAT(dec_response.err(), Not(IsEmpty()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
