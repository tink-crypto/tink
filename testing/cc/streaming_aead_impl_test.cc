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

#include "streaming_aead_impl.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/streamingaead/streaming_aead_config.h"
#include "tink/streamingaead/streaming_aead_key_templates.h"
#include "proto/testing/testing_api.grpc.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::StreamingAeadKeyTemplates;
using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;

using ::testing::Eq;
using ::testing::IsEmpty;
using ::tink_testing_api::StreamingAeadDecryptRequest;
using ::tink_testing_api::StreamingAeadEncryptRequest;
using ::tink_testing_api::StreamingAeadEncryptResponse;
using ::tink_testing_api::StreamingAeadDecryptResponse;

using crypto::tink::KeysetHandle;
using google::crypto::tink::KeyTemplate;

std::string ValidKeyset() {
  const KeyTemplate& key_template =
      StreamingAeadKeyTemplates::Aes128GcmHkdf4KB();
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

class StreamingAeadImplTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    ASSERT_TRUE(StreamingAeadConfig::Register().ok());
  }
};

TEST_F(StreamingAeadImplTest, EncryptDecryptSuccess) {
  tink_testing_api::StreamingAeadImpl streaming_aead;
  std::string keyset = ValidKeyset();
  StreamingAeadEncryptRequest enc_request;
  enc_request.set_keyset(keyset);
  enc_request.set_plaintext("Plain text");
  enc_request.set_associated_data("ad");
  StreamingAeadEncryptResponse enc_response;

  EXPECT_TRUE(streaming_aead.Encrypt(nullptr, &enc_request,
                                     &enc_response).ok());
  EXPECT_THAT(enc_response.err(), IsEmpty());

  StreamingAeadDecryptRequest dec_request;
  dec_request.set_keyset(keyset);
  dec_request.set_ciphertext(enc_response.ciphertext());
  dec_request.set_associated_data("ad");
  StreamingAeadDecryptResponse dec_response;

  EXPECT_TRUE(streaming_aead.Decrypt(nullptr, &dec_request,
                                     &dec_response).ok());
  EXPECT_THAT(dec_response.err(), IsEmpty());
  EXPECT_THAT(dec_response.plaintext(), Eq("Plain text"));
}

TEST_F(StreamingAeadImplTest, EncryptBadKeysetFail) {
  tink_testing_api::StreamingAeadImpl streaming_aead;
  StreamingAeadEncryptRequest enc_request;
  enc_request.set_keyset("bad keyset");
  enc_request.set_plaintext("Plain text");
  enc_request.set_associated_data("ad");
  StreamingAeadEncryptResponse enc_response;

  EXPECT_TRUE(streaming_aead.Encrypt(nullptr, &enc_request,
                                     &enc_response).ok());
  EXPECT_THAT(enc_response.err(), Not(IsEmpty()));
}

TEST_F(StreamingAeadImplTest, DecryptBadCiphertextFail) {
  tink_testing_api::StreamingAeadImpl streaming_aead;
  std::string keyset = ValidKeyset();
  StreamingAeadDecryptRequest dec_request;
  dec_request.set_keyset(keyset);
  dec_request.set_ciphertext("bad ciphertext");
  dec_request.set_associated_data("ad");
  StreamingAeadDecryptResponse dec_response;

  EXPECT_TRUE(streaming_aead.Decrypt(nullptr, &dec_request,
                                     &dec_response).ok());
  EXPECT_THAT(dec_response.err(), Not(IsEmpty()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
