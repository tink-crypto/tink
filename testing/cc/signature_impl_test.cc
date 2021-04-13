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

#include "signature_impl.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/signature/signature_config.h"
#include "tink/signature/signature_key_templates.h"
#include "proto/testing/testing_api.grpc.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::SignatureKeyTemplates;

using ::testing::IsEmpty;
using ::tink_testing_api::SignatureSignRequest;
using ::tink_testing_api::SignatureSignResponse;
using ::tink_testing_api::SignatureVerifyRequest;
using ::tink_testing_api::SignatureVerifyResponse;

using crypto::tink::KeysetHandle;
using google::crypto::tink::KeyTemplate;

std::string KeysetBytes(const KeysetHandle& keyset_handle) {
  std::stringbuf keyset;
  auto writer_result =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset));
  EXPECT_TRUE(writer_result.ok());
  auto status = CleartextKeysetHandle::Write(writer_result.ValueOrDie().get(),
                                             keyset_handle);
  EXPECT_TRUE(status.ok());
  return keyset.str();
}

class SignatureImplTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    ASSERT_TRUE(SignatureConfig::Register().ok());
  }
};

TEST_F(SignatureImplTest, SignVerifySuccess) {
  tink_testing_api::SignatureImpl signature;
  const KeyTemplate& key_template = SignatureKeyTemplates::EcdsaP256();
  auto private_handle_result = KeysetHandle::GenerateNew(key_template);
  EXPECT_TRUE(private_handle_result.ok());
  auto public_handle_result =
      private_handle_result.ValueOrDie()->GetPublicKeysetHandle();
  EXPECT_TRUE(public_handle_result.ok());

  SignatureSignRequest sign_request;
  sign_request.set_private_keyset(
      KeysetBytes(*private_handle_result.ValueOrDie()));
  sign_request.set_data("some data");
  SignatureSignResponse sign_response;

  EXPECT_TRUE(signature.Sign(nullptr, &sign_request, &sign_response).ok());
  EXPECT_THAT(sign_response.err(), IsEmpty());

  SignatureVerifyRequest verify_request;
  verify_request.set_public_keyset(
      KeysetBytes(*public_handle_result.ValueOrDie()));
  verify_request.set_signature(sign_response.signature());
  verify_request.set_data("some data");
  SignatureVerifyResponse verify_response;

  EXPECT_TRUE(
      signature.Verify(nullptr, &verify_request, &verify_response).ok());
  EXPECT_THAT(verify_response.err(), IsEmpty());
}

TEST_F(SignatureImplTest, SignBadKeysetFail) {
  tink_testing_api::SignatureImpl signature;
  SignatureSignRequest sign_request;
  sign_request.set_private_keyset("bad private keyset");
  sign_request.set_data("some data");
  SignatureSignResponse sign_response;

  EXPECT_TRUE(signature.Sign(nullptr, &sign_request, &sign_response).ok());
  EXPECT_THAT(sign_response.err(), Not(IsEmpty()));
}

TEST_F(SignatureImplTest, VerifyBadCiphertextFail) {
  tink_testing_api::SignatureImpl signature;
  const KeyTemplate& key_template = SignatureKeyTemplates::EcdsaP256();
  auto private_handle_result = KeysetHandle::GenerateNew(key_template);
  EXPECT_TRUE(private_handle_result.ok());
  auto public_handle_result =
      private_handle_result.ValueOrDie()->GetPublicKeysetHandle();
  EXPECT_TRUE(public_handle_result.ok());

  SignatureVerifyRequest verify_request;
  verify_request.set_public_keyset(
      KeysetBytes(*public_handle_result.ValueOrDie()));
  verify_request.set_signature("bad signature");
  verify_request.set_data("some data");
  SignatureVerifyResponse verify_response;

  EXPECT_TRUE(
      signature.Verify(nullptr, &verify_request, &verify_response).ok());
  EXPECT_THAT(verify_response.err(), Not(IsEmpty()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
