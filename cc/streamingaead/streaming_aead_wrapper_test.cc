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
#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/input_stream.h"
#include "tink/output_stream.h"
#include "tink/primitive_set.h"
#include "tink/random_access_stream.h"
#include "tink/streaming_aead.h"
#include "tink/subtle/random.h"
#include "tink/subtle/test_util.h"
#include "tink/util/buffer.h"
#include "tink/util/file_random_access_stream.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using crypto::tink::test::DummyStreamingAead;
using crypto::tink::test::IsOk;
using crypto::tink::test::StatusIs;
using google::crypto::tink::KeysetInfo;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::OutputPrefixType;
using subtle::test::ReadFromStream;
using subtle::test::WriteToStream;
using testing::HasSubstr;

// Creates a RandomAccessStream with the specified contents.
std::unique_ptr<RandomAccessStream> GetRandomAccessStream(
    absl::string_view contents) {
  static int index = 1;
  std::string filename = absl::StrCat("stream_data_file_", index, ".txt");
  index++;
  int input_fd = test::GetTestFileDescriptor(filename, contents);
  return {absl::make_unique<util::FileRandomAccessStream>(input_fd)};
}

// Reads the entire 'ra_stream', until no more bytes can be read,
// and puts the read bytes into 'contents'.
// Returns the status of the last ra_stream->PRead()-operation.
util::Status ReadAll(RandomAccessStream* ra_stream, std::string* contents) {
  int chunk_size = 42;
  contents->clear();
  auto buffer = std::move(util::Buffer::New(chunk_size).ValueOrDie());
  int64_t position = 0;
  auto status = ra_stream->PRead(position, chunk_size, buffer.get());
  while (status.ok()) {
    contents->append(buffer->get_mem_block(), buffer->size());
    position = contents->size();
    status = ra_stream->PRead(position, chunk_size, buffer.get());
  }
  if (status.code() == absl::StatusCode::kOutOfRange) {  // EOF
    EXPECT_EQ(0, buffer->size());
  }
  return status;
}

// A container for specification of instances of DummyStreamingAead
// to be created for testing.
struct StreamingAeadSpec {
  uint32_t key_id;
  std::string saead_name;
  OutputPrefixType output_prefix_type;
};

// Generates a PrimitiveSet<StreamingAead> with DummyStreamingAead
// instances according to the specification in 'spec'.
// The last entry in 'spec' will be the primary primitive in the returned set.
std::unique_ptr<PrimitiveSet<StreamingAead>> GetTestStreamingAeadSet(
    const std::vector<StreamingAeadSpec>& spec) {
  auto saead_set = absl::make_unique<PrimitiveSet<StreamingAead>>();
  int i = 0;
  for (auto& s : spec) {
    KeysetInfo::KeyInfo key_info;
    key_info.set_output_prefix_type(s.output_prefix_type);
    key_info.set_key_id(s.key_id);
    key_info.set_status(KeyStatusType::ENABLED);
    std::unique_ptr<StreamingAead> saead =
        absl::make_unique<DummyStreamingAead>(s.saead_name);
    auto entry_result = saead_set->AddPrimitive(std::move(saead), key_info);
    EXPECT_TRUE(entry_result.ok());
    if (i + 1 == spec.size()) {
      EXPECT_THAT(saead_set->set_primary(entry_result.ValueOrDie()), IsOk());
    }
    i++;
  }
  return saead_set;
}

TEST(StreamingAeadSetWrapperTest, WrapNullptr) {
  StreamingAeadWrapper wrapper;
  auto result = wrapper.Wrap(nullptr);
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(absl::StatusCode::kInternal, result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                      std::string(result.status().message()));
}

TEST(StreamingAeadSetWrapperTest, WrapEmpty) {
  StreamingAeadWrapper wrapper;
  auto result = wrapper.Wrap(absl::make_unique<PrimitiveSet<StreamingAead>>());
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                      std::string(result.status().message()));
}

TEST(StreamingAeadSetWrapperTest, BasicEncryptionAndDecryption) {
  uint32_t key_id_0 = 1234543;
  uint32_t key_id_1 = 726329;
  uint32_t key_id_2 = 7213743;
  std::string saead_name_0 = "streaming_aead0";
  std::string saead_name_1 = "streaming_aead1";
  std::string saead_name_2 = "streaming_aead2";

  auto saead_set = GetTestStreamingAeadSet(
      {{key_id_0, saead_name_0, OutputPrefixType::RAW},
       {key_id_1, saead_name_1, OutputPrefixType::RAW},
       {key_id_2, saead_name_2, OutputPrefixType::RAW}});

  // Wrap saead_set and test the resulting StreamingAead.
  StreamingAeadWrapper wrapper;
  auto wrap_result = wrapper.Wrap(std::move(saead_set));
  EXPECT_TRUE(wrap_result.ok()) << wrap_result.status();
  auto saead = std::move(wrap_result.ValueOrDie());
  for (int pt_size : {0, 1, 10, 100, 10000}) {
    std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
    for (std::string aad : {"some_aad", "", "some other aad"}) {
      SCOPED_TRACE(absl::StrCat("pt_size = ", pt_size,
                                ", aad = '", aad, "'"));

      // Prepare ciphertext destination stream.
      auto ct_stream = absl::make_unique<std::stringstream>();
      // A reference to the ciphertext buffer, for later validation.
      auto ct_buf = ct_stream->rdbuf();
      std::unique_ptr<OutputStream> ct_destination(
          absl::make_unique<util::OstreamOutputStream>(std::move(ct_stream)));
      // Encrypt the plaintext.
      auto enc_stream_result =
          saead->NewEncryptingStream(std::move(ct_destination), aad);
      EXPECT_THAT(enc_stream_result.status(), IsOk());
      auto enc_stream = std::move(enc_stream_result.ValueOrDie());
      auto status = WriteToStream(enc_stream.get(), plaintext);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(absl::StrCat(saead_name_2, aad, plaintext), ct_buf->str());
      // Prepare ciphertext source stream.
      auto ct_source_stream =
          absl::make_unique<std::stringstream>(ct_buf->str());
      std::unique_ptr<InputStream> ct_source(
          absl::make_unique<util::IstreamInputStream>(
              std::move(ct_source_stream)));
      // Decrypt the ciphertext.
      auto dec_stream_result =
          saead->NewDecryptingStream(std::move(ct_source), aad);
      EXPECT_THAT(dec_stream_result.status(), IsOk());
      std::string decrypted;
      status = ReadFromStream(dec_stream_result.ValueOrDie().get(), &decrypted);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(plaintext, decrypted);
    }
  }
}

TEST(StreamingAeadSetWrapperTest, DecryptionWithRandomAccessStream) {
  uint32_t key_id_0 = 1234543;
  uint32_t key_id_1 = 726329;
  uint32_t key_id_2 = 7213743;
  std::string saead_name_0 = "streaming_aead0";
  std::string saead_name_1 = "streaming_aead1";
  std::string saead_name_2 = "streaming_aead2";

  auto saead_set = GetTestStreamingAeadSet(
      {{key_id_0, saead_name_0, OutputPrefixType::RAW},
       {key_id_1, saead_name_1, OutputPrefixType::RAW},
       {key_id_2, saead_name_2, OutputPrefixType::RAW}});

  // Wrap saead_set and test the resulting StreamingAead.
  StreamingAeadWrapper wrapper;
  auto wrap_result = wrapper.Wrap(std::move(saead_set));
  EXPECT_TRUE(wrap_result.ok()) << wrap_result.status();
  auto saead = std::move(wrap_result.ValueOrDie());
  for (int pt_size : {0, 1, 10, 100, 10000}) {
    std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
    for (std::string aad : {"some_aad", "", "some other aad"}) {
      SCOPED_TRACE(absl::StrCat("pt_size = ", pt_size,
                                ", aad = '", aad, "'"));

      // Prepare ciphertext destination stream.
      auto ct_stream = absl::make_unique<std::stringstream>();
      // A reference to the ciphertext buffer, for later validation.
      auto ct_buf = ct_stream->rdbuf();
      std::unique_ptr<OutputStream> ct_destination(
          absl::make_unique<util::OstreamOutputStream>(std::move(ct_stream)));

      // Encrypt the plaintext.
      auto enc_stream_result =
          saead->NewEncryptingStream(std::move(ct_destination), aad);
      EXPECT_THAT(enc_stream_result.status(), IsOk());
      auto enc_stream = std::move(enc_stream_result.ValueOrDie());
      auto status = WriteToStream(enc_stream.get(), plaintext);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(absl::StrCat(saead_name_2, aad, plaintext), ct_buf->str());

      // Decrypt the ciphertext.
      auto ct_source = GetRandomAccessStream(ct_buf->str());
      auto dec_stream_result =
          saead->NewDecryptingRandomAccessStream(std::move(ct_source), aad);
      EXPECT_THAT(dec_stream_result.status(), IsOk());
      std::string decrypted;
      status = ReadAll(dec_stream_result.ValueOrDie().get(), &decrypted);
      EXPECT_THAT(status, StatusIs(absl::StatusCode::kOutOfRange,
                                   HasSubstr("EOF")));
      EXPECT_EQ(plaintext, decrypted);
    }
  }
}

TEST(StreamingAeadSetWrapperTest, DecryptionAfterWrapperIsDestroyed) {
  uint32_t key_id_0 = 1234543;
  uint32_t key_id_1 = 726329;
  uint32_t key_id_2 = 7213743;
  std::string saead_name_0 = "streaming_aead0";
  std::string saead_name_1 = "streaming_aead1";
  std::string saead_name_2 = "streaming_aead2";

  auto saead_set = GetTestStreamingAeadSet(
      {{key_id_0, saead_name_0, OutputPrefixType::RAW},
       {key_id_1, saead_name_1, OutputPrefixType::RAW},
       {key_id_2, saead_name_2, OutputPrefixType::RAW}});

  int pt_size = 100;
  std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
  std::string aad = "some_aad";
  std::unique_ptr<InputStream> dec_stream;
  {
    // Wrap saead_set and test the resulting StreamingAead.
    StreamingAeadWrapper wrapper;
    auto wrap_result = wrapper.Wrap(std::move(saead_set));
    EXPECT_TRUE(wrap_result.ok()) << wrap_result.status();
    auto saead = std::move(wrap_result.ValueOrDie());

    // Prepare ciphertext destination stream.
    auto ct_stream = absl::make_unique<std::stringstream>();
    // A reference to the ciphertext buffer, for later validation.
    auto ct_buf = ct_stream->rdbuf();
    std::unique_ptr<OutputStream> ct_destination(
        absl::make_unique<util::OstreamOutputStream>(std::move(ct_stream)));
    // Encrypt the plaintext.
    auto enc_stream_result =
        saead->NewEncryptingStream(std::move(ct_destination), aad);
    EXPECT_THAT(enc_stream_result.status(), IsOk());
    auto enc_stream = std::move(enc_stream_result.ValueOrDie());
    auto status = WriteToStream(enc_stream.get(), plaintext);
    EXPECT_THAT(status, IsOk());
    EXPECT_EQ(absl::StrCat(saead_name_2, aad, plaintext), ct_buf->str());
    // Prepare ciphertext source stream.
    auto ct_source_stream =
        absl::make_unique<std::stringstream>(ct_buf->str());
    std::unique_ptr<InputStream> ct_source(
        absl::make_unique<util::IstreamInputStream>(
            std::move(ct_source_stream)));
    // Decrypt the ciphertext.
    auto dec_stream_result =
        saead->NewDecryptingStream(std::move(ct_source), aad);
    EXPECT_THAT(dec_stream_result.status(), IsOk());
    dec_stream = std::move(dec_stream_result.ValueOrDie());
  }
  // Now wrapper and saead are out of scope,
  // but decrypting stream should still work.
  std::string decrypted;
  auto status = ReadFromStream(dec_stream.get(), &decrypted);
  EXPECT_THAT(status, IsOk());
  EXPECT_EQ(plaintext, decrypted);
}

TEST(StreamingAeadSetWrapperTest, MissingRawPrimitives) {
  uint32_t key_id_0 = 1234543;
  uint32_t key_id_1 = 726329;
  uint32_t key_id_2 = 7213743;
  std::string saead_name_0 = "streaming_aead0";
  std::string saead_name_1 = "streaming_aead1";
  std::string saead_name_2 = "streaming_aead2";

  auto saead_set = GetTestStreamingAeadSet(
      {{key_id_0, saead_name_0, OutputPrefixType::TINK},
       {key_id_1, saead_name_1, OutputPrefixType::LEGACY},
       {key_id_2, saead_name_2, OutputPrefixType::TINK}});

  // Wrap saead_set and test the resulting StreamingAead.
  StreamingAeadWrapper wrapper;
  auto wrap_result = wrapper.Wrap(std::move(saead_set));
  EXPECT_THAT(wrap_result.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                             HasSubstr("no raw primitives")));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
