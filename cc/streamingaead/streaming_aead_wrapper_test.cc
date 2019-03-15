// Copyright 2019 Google Inc.
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

#include "tink/streamingaead/streaming_aead_wrapper.h"

#include <sstream>

#include "gtest/gtest.h"
#include "tink/primitive_set.h"
#include "tink/streaming_aead.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/status.h"
#include "tink/util/test_util.h"

using crypto::tink::test::DummyStreamingAead;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace {

TEST(StreamingAeadSetWrapperTest, WrapNullptr) {
  StreamingAeadWrapper wrapper;
  auto result = wrapper.Wrap(nullptr);
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(util::error::INTERNAL, result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                      result.status().error_message());
}

TEST(StreamingAeadSetWrapperTest, WrapEmpty) {
  StreamingAeadWrapper wrapper;
  auto result = wrapper.Wrap(absl::make_unique<PrimitiveSet<StreamingAead>>());
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                      result.status().error_message());
}

TEST(StreamingAeadSetWrapperTest, Basic) {
  Keyset::Key* key;
  Keyset keyset;

  uint32_t key_id_0 = 1234543;
  key = keyset.add_key();
  key->set_output_prefix_type(OutputPrefixType::TINK);
  key->set_key_id(key_id_0);
  key->set_status(KeyStatusType::ENABLED);

  uint32_t key_id_1 = 726329;
  key = keyset.add_key();
  key->set_output_prefix_type(OutputPrefixType::LEGACY);
  key->set_key_id(key_id_1);
  key->set_status(KeyStatusType::ENABLED);

  uint32_t key_id_2 = 7213743;
  key = keyset.add_key();
  key->set_output_prefix_type(OutputPrefixType::TINK);
  key->set_key_id(key_id_2);
  key->set_status(KeyStatusType::ENABLED);

  std::string saead_name_0 = "streaming_aead0";
  std::string saead_name_1 = "streaming_aead1";
  std::string saead_name_2 = "streaming_aead2";
  std::unique_ptr<PrimitiveSet<StreamingAead>> saead_set(
      new PrimitiveSet<StreamingAead>());

  std::unique_ptr<StreamingAead> saead =
      absl::make_unique<DummyStreamingAead>(saead_name_0);
  auto entry_result = saead_set->AddPrimitive(std::move(saead), keyset.key(0));
  ASSERT_TRUE(entry_result.ok());

  saead = absl::make_unique<DummyStreamingAead>(saead_name_1);
  entry_result = saead_set->AddPrimitive(std::move(saead), keyset.key(1));
  ASSERT_TRUE(entry_result.ok());

  saead = absl::make_unique<DummyStreamingAead>(saead_name_2);
  entry_result = saead_set->AddPrimitive(std::move(saead), keyset.key(2));
  ASSERT_TRUE(entry_result.ok());
  // The last key is the primary.
  saead_set->set_primary(entry_result.ValueOrDie());

  // Wrap aead_set and test the resulting StreamingAead.
  StreamingAeadWrapper wrapper;
  auto wrap_result = wrapper.Wrap(std::move(saead_set));
  EXPECT_TRUE(wrap_result.ok()) << wrap_result.status();
  saead = std::move(wrap_result.ValueOrDie());
  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";

  // Prepare ciphertext destination stream.
  auto ct_stream = absl::make_unique<std::stringstream>();
  // A reference to the ciphertext buffer, for later validation.
  auto ct_buf = ct_stream->rdbuf();
  std::unique_ptr<OutputStream> ct_destination(
      absl::make_unique<util::OstreamOutputStream>(std::move(ct_stream)));

  auto encrypt_result =
      saead->NewEncryptingStream(std::move(ct_destination), aad);
  EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
  auto encrypting_stream = std::move(encrypt_result.ValueOrDie());
  auto status = encrypting_stream->Close();
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(absl::StrCat(saead_name_2, aad), ct_buf->str());

  // Prepare ciphertext source stream.
  ct_stream = absl::make_unique<std::stringstream>();
  // A reference to the ciphertext buffer, for later validation.
  ct_buf = ct_stream->rdbuf();
  std::unique_ptr<InputStream> ct_source(
      absl::make_unique<util::IstreamInputStream>(std::move(ct_stream)));
  auto decrypt_result = saead->NewDecryptingStream(std::move(ct_source), aad);
  EXPECT_FALSE(decrypt_result.ok());
  EXPECT_EQ(util::error::UNIMPLEMENTED, decrypt_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "Not implemented yet",
                      decrypt_result.status().error_message());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
