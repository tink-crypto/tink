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

#include "create.h"

#include <memory>
#include <ostream>

#include <sstream>

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/binary_keyset_writer.h"
#include "tink/keyset_handle.h"
#include "tink/mac.h"
#include "aead_impl.h"

namespace tink_testing_api {

namespace {

using ::google::crypto::tink::KeyTemplate;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::NotNull;

std::string ValidAeadKeyset() {
  const KeyTemplate& key_template = crypto::tink::AeadKeyTemplates::Aes128Eax();
  auto handle_result = crypto::tink::KeysetHandle::GenerateNew(key_template);
  EXPECT_TRUE(handle_result.ok());
  std::stringbuf keyset;
  auto writer_result = crypto::tink::BinaryKeysetWriter::New(
      absl::make_unique<std::ostream>(&keyset));
  EXPECT_TRUE(writer_result.ok());

  auto status = crypto::tink::CleartextKeysetHandle::Write(
      writer_result.value().get(), *handle_result.value());
  EXPECT_TRUE(status.ok());
  return keyset.str();
}

class CreateTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    ASSERT_TRUE(crypto::tink::AeadConfig::Register().ok());
  }
};

TEST_F(CreateTest, RpcHelperSuccess) {
  std::string keyset = ValidAeadKeyset();
  CreationRequest request;
  request.set_keyset(keyset);
  CreationResponse response;

  EXPECT_TRUE(
      CreatePrimitiveForRpc<crypto::tink::Aead>(&request, &response)
          .ok());
  EXPECT_THAT(response.err(), IsEmpty());
}

TEST_F(CreateTest, RpcHelperWrongPrimitiveFails) {
  std::string keyset = ValidAeadKeyset();
  CreationRequest request;
  request.set_keyset(keyset);
  CreationResponse response;
  EXPECT_TRUE(
      CreatePrimitiveForRpc<crypto::tink::Mac>(&request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

TEST_F(CreateTest, PrimitiveCreationWorks) {
  std::string keyset = ValidAeadKeyset();
  crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::Aead>> aead =
      PrimitiveFromSerializedBinaryProtoKeyset<crypto::tink::Aead>(keyset);
  ASSERT_TRUE(aead.status().ok()) << aead.status();
  EXPECT_THAT(*aead, NotNull());
}

TEST_F(CreateTest, PrimitiveCreationWrongPrimitiveFails) {
  std::string keyset = ValidAeadKeyset();
  crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::Mac>> aead =
      PrimitiveFromSerializedBinaryProtoKeyset<crypto::tink::Mac>(keyset);
  ASSERT_FALSE(aead.status().ok());
}


}  // namespace

}  // namespace tink_testing_api
