// Copyright 2020 Google LLC
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

#include "tink/util/fake_kms_client.h"

#include <cstdlib>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/kms_aead.pb.h"
#include "proto/kms_envelope.pb.h"

using ::crypto::tink::test::IsOk;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::KmsAeadKeyFormat;
using google::crypto::tink::KmsEnvelopeAeadKeyFormat;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace test {
namespace {

// TODO(b/174740983) Add this function to aead_key_templates.
KeyTemplate NewKmsAeadKeyTemplate(std::string key_uri) {
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.KmsAeadKey");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  KmsAeadKeyFormat key_format;
  key_format.set_key_uri(key_uri);
  key_format.SerializeToString(key_template.mutable_value());
  return key_template;
}

// TODO(b/174740983) Add this function to aead_key_templates.
KeyTemplate NewKmsEnvelopeKeyTemplate(std::string key_uri,
                                      const KeyTemplate& dek_template) {
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  KmsEnvelopeAeadKeyFormat key_format;
  key_format.set_kek_uri(key_uri);
  key_format.mutable_dek_template()->MergeFrom(dek_template);
  key_format.SerializeToString(key_template.mutable_value());
  return key_template;
}

class FakeKmsClientTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() { ASSERT_TRUE(AeadConfig::Register().ok()); }
};

TEST_F(FakeKmsClientTest, CreateNewAeadSuccess) {
  auto uri_result = FakeKmsClient::CreateFakeKeyUri();
  EXPECT_TRUE(uri_result.ok()) << uri_result.status();
  std::string key_uri = uri_result.ValueOrDie();

  auto client_result = FakeKmsClient::New(key_uri, "");
  EXPECT_TRUE(client_result.ok()) << client_result.status();
  auto client = std::move(client_result.ValueOrDie());
  EXPECT_TRUE(client->DoesSupport(key_uri));

  auto aead_result = client->GetAead(key_uri);
  EXPECT_TRUE(aead_result.ok()) << aead_result.status();
  auto aead = std::move(aead_result.ValueOrDie());

  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";
  auto encrypt_result = aead->Encrypt(plaintext, aad);
  EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
  std::string ciphertext = encrypt_result.ValueOrDie();
  auto decrypt_result = aead->Decrypt(ciphertext, aad);
  EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
  EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
}

TEST_F(FakeKmsClientTest, ClientIsBound) {
  std::string key_uri =
      "fake-kms://"
      "CL3oi0kSVwpMCjB0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNF"
      "YXhLZXkSFhICCBAaEPFnQNgtxEG0vEek8bBfgL8YARABGL3oi0kgAQ";
  auto client_result = FakeKmsClient::New(key_uri, "");
  EXPECT_TRUE(client_result.ok()) << client_result.status();
  auto client = std::move(client_result.ValueOrDie());

  // No other key_uri is accepted, even a valid one.
  std::string another_key_uri =
      "fake-kms://"
      "CO3y2NgHElgKTAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVz"
      "RWF4S2V5EhYSAggQGhALi4dQMjUR0faRYElRXi__GAEQARjt8tjYByAB";
  EXPECT_FALSE(client->DoesSupport(another_key_uri));
  auto aead_result = client->GetAead(another_key_uri);
  EXPECT_FALSE(aead_result.ok());
}

TEST_F(FakeKmsClientTest, ClientIsUnbound) {
  auto client_result = FakeKmsClient::New("", "");
  EXPECT_TRUE(client_result.ok()) << client_result.status();
  auto client = std::move(client_result.ValueOrDie());

  // All valid 'fake-kms' key_uris are accepted.
  std::string uri =
      "fake-kms://"
      "CL3oi0kSVwpMCjB0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNF"
      "YXhLZXkSFhICCBAaEPFnQNgtxEG0vEek8bBfgL8YARABGL3oi0kgAQ";
  EXPECT_TRUE(client->DoesSupport(uri));
  auto aead_result = client->GetAead(uri);
  EXPECT_TRUE(aead_result.ok());

  std::string another_uri =
      "fake-kms://"
      "CO3y2NgHElgKTAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVz"
      "RWF4S2V5EhYSAggQGhALi4dQMjUR0faRYElRXi__GAEQARjt8tjYByAB";
  EXPECT_TRUE(client->DoesSupport(another_uri));
  auto another_aead_result = client->GetAead(another_uri);
  EXPECT_TRUE(another_aead_result.ok()) << another_aead_result.status();
}

TEST_F(FakeKmsClientTest, RegisterAndEncryptDecryptWithKmsAead) {
  auto uri_result = FakeKmsClient::CreateFakeKeyUri();
  EXPECT_TRUE(uri_result.ok()) << uri_result.status();
  std::string key_uri = uri_result.ValueOrDie();
  auto status = FakeKmsClient::RegisterNewClient(key_uri, "");
  EXPECT_THAT(status, IsOk());

  KeyTemplate key_template = NewKmsAeadKeyTemplate(key_uri);
  auto handle_result = KeysetHandle::GenerateNew(key_template);
  EXPECT_TRUE(handle_result.ok()) << handle_result.status();
  auto aead_result =
      handle_result.ValueOrDie()->GetPrimitive<crypto::tink::Aead>();
  EXPECT_TRUE(aead_result.ok()) << aead_result.status();
  auto aead = std::move(aead_result.ValueOrDie());

  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";
  auto encrypt_result = aead->Encrypt(plaintext, aad);
  EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
  std::string ciphertext = encrypt_result.ValueOrDie();
  auto decrypt_result = aead->Decrypt(ciphertext, aad);
  EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
  EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
}

TEST_F(FakeKmsClientTest, RegisterAndEncryptDecryptWithKmsEnvelopeAead) {
  auto uri_result = FakeKmsClient::CreateFakeKeyUri();
  EXPECT_TRUE(uri_result.ok()) << uri_result.status();
  std::string key_uri = uri_result.ValueOrDie();
  auto status = FakeKmsClient::RegisterNewClient(key_uri, "");
  EXPECT_THAT(status, IsOk());

  KeyTemplate key_template =
      NewKmsEnvelopeKeyTemplate(key_uri, AeadKeyTemplates::Aes128Gcm());
  auto handle_result = KeysetHandle::GenerateNew(key_template);
  EXPECT_TRUE(handle_result.ok()) << handle_result.status();
  auto aead_result =
      handle_result.ValueOrDie()->GetPrimitive<crypto::tink::Aead>();
  EXPECT_TRUE(aead_result.ok()) << aead_result.status();
  auto aead = std::move(aead_result.ValueOrDie());

  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";
  auto encrypt_result = aead->Encrypt(plaintext, aad);
  EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
  std::string ciphertext = encrypt_result.ValueOrDie();
  auto decrypt_result = aead->Decrypt(ciphertext, aad);
  EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
  EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
}

// TODO(b/174740983): Add test where an unbounded KeyClient is registered.
// This is not yet implemented as it would break the isolation of the tests:
// Once a unbounded client is registered, it can't currently be unregistered.

}  // namespace
}  // namespace test
}  // namespace tink
}  // namespace crypto
