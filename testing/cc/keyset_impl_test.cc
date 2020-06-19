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

#include "keyset_impl.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/binary_keyset_reader.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/config/tink_config.h"
#include "proto/testing/testing_api.grpc.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::AeadKeyTemplates;
using ::crypto::tink::BinaryKeysetReader;
using ::crypto::tink::CleartextKeysetHandle;
using google::crypto::tink::KeyTemplate;
using ::testing::IsEmpty;
using tink_testing_api::KeysetGenerateRequest;
using tink_testing_api::KeysetGenerateResponse;

class KeysetImplTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() { ASSERT_TRUE(TinkConfig::Register().ok()); }
};

TEST_F(KeysetImplTest, GenerateSuccess) {
  tink_testing_api::KeysetImpl keyset;
  const KeyTemplate& key_template = AeadKeyTemplates::Aes128Eax();
  KeysetGenerateRequest request;
  std::string templ;
  EXPECT_TRUE(key_template.SerializeToString(&templ));
  request.set_template_(templ);
  KeysetGenerateResponse response;

  EXPECT_TRUE(keyset.Generate(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), IsEmpty());

  auto reader_result = BinaryKeysetReader::New(response.keyset());
  ASSERT_TRUE(reader_result.ok());
  auto handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.ValueOrDie()));
  EXPECT_TRUE(handle_result.ok());
}

TEST_F(KeysetImplTest, GenerateFail) {
  tink_testing_api::KeysetImpl keyset;

  KeysetGenerateRequest request;
  request.set_template_("bad template");
  KeysetGenerateResponse response;
  EXPECT_TRUE(keyset.Generate(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
