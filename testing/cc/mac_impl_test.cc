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

#include "mac_impl.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/mac/mac_config.h"
#include "tink/mac/mac_key_templates.h"
#include "proto/testing_api.grpc.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::MacKeyTemplates;

using ::testing::IsEmpty;
using ::tink_testing_api::ComputeMacRequest;
using ::tink_testing_api::ComputeMacResponse;
using ::tink_testing_api::CreationRequest;
using ::tink_testing_api::CreationResponse;
using ::tink_testing_api::VerifyMacRequest;
using ::tink_testing_api::VerifyMacResponse;

using crypto::tink::KeysetHandle;
using google::crypto::tink::KeyTemplate;

std::string ValidKeyset() {
  const KeyTemplate& key_template = MacKeyTemplates::HmacSha256();
  auto handle_result = KeysetHandle::GenerateNew(key_template);
  EXPECT_TRUE(handle_result.ok());
  std::stringbuf keyset;
  auto writer_result =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset));
  EXPECT_TRUE(writer_result.ok());

  auto status = CleartextKeysetHandle::Write(writer_result.value().get(),
                                             *handle_result.value());
  EXPECT_TRUE(status.ok());
  return keyset.str();
}

class MacImplTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() { ASSERT_TRUE(MacConfig::Register().ok()); }
};

TEST_F(MacImplTest, CreateMacSuccess) {
  tink_testing_api::MacImpl mac;
  std::string keyset = ValidKeyset();
  CreationRequest request;
  request.set_keyset(keyset);
  CreationResponse response;

  EXPECT_TRUE(mac.Create(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), IsEmpty());
}

TEST_F(MacImplTest, CreateMacFails) {
  tink_testing_api::MacImpl mac;
  CreationRequest request;
  request.set_keyset("bad keyset");
  CreationResponse response;

  EXPECT_TRUE(mac.Create(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

TEST_F(MacImplTest, ComputeVerifySuccess) {
  tink_testing_api::MacImpl mac;
  std::string keyset = ValidKeyset();
  ComputeMacRequest comp_request;
  comp_request.set_keyset(keyset);
  comp_request.set_data("some data");
  ComputeMacResponse comp_response;

  EXPECT_TRUE(mac.ComputeMac(nullptr, &comp_request, &comp_response).ok());
  EXPECT_THAT(comp_response.err(), IsEmpty());

  VerifyMacRequest verify_request;
  verify_request.set_keyset(keyset);
  verify_request.set_mac_value(comp_response.mac_value());
  verify_request.set_data("some data");
  VerifyMacResponse verify_response;

  EXPECT_TRUE(mac.VerifyMac(nullptr, &verify_request, &verify_response).ok());
  EXPECT_THAT(verify_response.err(), IsEmpty());
}

TEST_F(MacImplTest, ComputeBadKeysetFail) {
  tink_testing_api::MacImpl mac;
  ComputeMacRequest comp_request;
  comp_request.set_keyset("bad keyset");
  comp_request.set_data("some data");
  ComputeMacResponse comp_response;

  EXPECT_TRUE(mac.ComputeMac(nullptr, &comp_request, &comp_response).ok());
  EXPECT_THAT(comp_response.err(), Not(IsEmpty()));
}

TEST_F(MacImplTest, VerifyBadCiphertextFail) {
  tink_testing_api::MacImpl mac;
  std::string keyset = ValidKeyset();
  VerifyMacRequest verify_request;
  verify_request.set_keyset(keyset);
  verify_request.set_mac_value("bad mac value");
  verify_request.set_data("some data");
  VerifyMacResponse verify_response;

  EXPECT_TRUE(mac.VerifyMac(nullptr, &verify_request, &verify_response).ok());
  EXPECT_THAT(verify_response.err(), Not(IsEmpty()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
