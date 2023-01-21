// Copyright 2019 Google LLC
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
#include "tink/util/test_util.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "tink/internal/test_random_access_stream.h"
#include "tink/output_stream.h"
#include "tink/random_access_stream.h"
#include "tink/subtle/random.h"
#include "tink/subtle/test_util.h"
#include "tink/util/buffer.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace test {
namespace {

using ::crypto::tink::internal::TestRandomAccessStream;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Not;

TEST(AsKeyDataTest, Basic) {
  AesGcmKey key;
  key.set_key_value(crypto::tink::subtle::Random::GetRandomBytes(11));

  KeyData key_data = AsKeyData(key, KeyData::SYMMETRIC);

  EXPECT_THAT(key_data.type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));
  EXPECT_THAT(key_data.key_material_type(), Eq(KeyData::SYMMETRIC));
  AesGcmKey deserialized_key;
  EXPECT_TRUE(deserialized_key.ParseFromString(key_data.value()));
  EXPECT_THAT(deserialized_key.key_value(), Eq(key.key_value()));
}

TEST(DummyTests, Aead) {
  EXPECT_THAT(DummyAead("dummy").Encrypt("foo", "bar").value(),
              Eq("5:3:dummybarfoo"));
}

TEST(DummyTests, AeadCord) {
  absl::Cord plaintext;
  plaintext.Append("foo");
  absl::Cord aad;
  aad.Append("bar");

  EXPECT_THAT(DummyCordAead("dummy").Encrypt(plaintext, aad).value(),
              Eq("5:3:dummybarfoo"));
}

TEST(DummyTests, AeadCordMultipleChunks) {
  absl::Cord plaintext;
  plaintext.Append("f");
  plaintext.Append("o");
  plaintext.Append("o");
  absl::Cord aad;
  aad.Append("b");
  aad.Append("a");
  aad.Append("r");

  EXPECT_THAT(DummyCordAead("dummy").Encrypt(plaintext, aad).value(),
              Eq("5:3:dummybarfoo"));
}

TEST(ZTests, UniformString) {
  EXPECT_THAT(ZTestUniformString(std::string(32, 0xaa)), IsOk());
  EXPECT_THAT(ZTestUniformString(std::string(32, 0x00)), Not(IsOk()));
  EXPECT_THAT(ZTestUniformString(subtle::Random::GetRandomBytes(32)), IsOk());
}

TEST(ZTests, CrossCorrelationUniformString) {
  EXPECT_THAT(ZTestCrosscorrelationUniformStrings(std::string(32, 0xaa),
                                                  std::string(32, 0x99)),
              IsOk());
  EXPECT_THAT(ZTestCrosscorrelationUniformStrings(std::string(32, 0xaa),
                                                  std::string(32, 0xaa)),
              Not(IsOk()));
  EXPECT_THAT(
      ZTestCrosscorrelationUniformStrings(subtle::Random::GetRandomBytes(32),
                                          subtle::Random::GetRandomBytes(32)),
      IsOk());
}

TEST(ZTests, AutocorrelationUniformString) {
  EXPECT_THAT(ZTestAutocorrelationUniformString(std::string(32, 0xaa)),
              Not(IsOk()));
  EXPECT_THAT(ZTestAutocorrelationUniformString(std::string(
                  "This is a text that is only ascii characters and therefore "
                  "not random. It needs quite a few characters before it has "
                  "enough to find a pattern, though, as it is text.")),
              Not(IsOk()));
  EXPECT_THAT(
      ZTestAutocorrelationUniformString(subtle::Random::GetRandomBytes(32)),
      IsOk());
}

TEST(DummyStreamingAead, DummyDecryptingStreamPreadAllAtOnceSucceeds) {
  const int stream_size = 1024;
  std::string stream_content = subtle::Random::GetRandomBytes(stream_size);

  auto ostream = std::make_unique<std::ostringstream>();
  auto string_stream_buffer = ostream->rdbuf();
  auto output_stream =
      std::make_unique<util::OstreamOutputStream>(std::move(ostream));

  DummyStreamingAead streaming_aead("Some AEAD");
  util::StatusOr<std::unique_ptr<OutputStream>> encrypting_output_stream =
      streaming_aead.NewEncryptingStream(std::move(output_stream), "Some AAD");
  ASSERT_THAT(encrypting_output_stream.status(), IsOk());
  ASSERT_THAT(subtle::test::WriteToStream(
                  encrypting_output_stream.value().get(), stream_content),
              IsOk());

  std::string ciphertext = string_stream_buffer->str();
  auto test_random_access_stream =
      std::make_unique<TestRandomAccessStream>(ciphertext);
  util::StatusOr<std::unique_ptr<RandomAccessStream>>
      decrypting_random_access_stream =
          streaming_aead.NewDecryptingRandomAccessStream(
              std::move(test_random_access_stream), "Some AAD");
  ASSERT_THAT(decrypting_random_access_stream.status(), IsOk());

  auto buffer = util::Buffer::New(ciphertext.size());
  EXPECT_THAT((*decrypting_random_access_stream)
                  ->PRead(/*position=*/0, ciphertext.size(), buffer->get()),
              StatusIs(absl::StatusCode::kOutOfRange));
  EXPECT_EQ(stream_content,
            std::string((*buffer)->get_mem_block(), (*buffer)->size()));
}

TEST(DummyStreamingAead, DummyDecryptingStreamPreadInChunksSucceeds) {
  const int stream_size = 1024;
  std::string stream_content = subtle::Random::GetRandomBytes(stream_size);

  auto ostream = std::make_unique<std::ostringstream>();
  auto string_stream_buffer = ostream->rdbuf();
  auto output_stream =
      std::make_unique<util::OstreamOutputStream>(std::move(ostream));

  DummyStreamingAead streaming_aead("Some AEAD");
  util::StatusOr<std::unique_ptr<OutputStream>> encrypting_output_stream =
      streaming_aead.NewEncryptingStream(std::move(output_stream), "Some AAD");
  ASSERT_THAT(encrypting_output_stream.status(), IsOk());
  ASSERT_THAT(subtle::test::WriteToStream(
                  encrypting_output_stream.value().get(), stream_content),
              IsOk());

  std::string ciphertext = string_stream_buffer->str();
  auto test_random_access_stream =
      std::make_unique<TestRandomAccessStream>(ciphertext);
  util::StatusOr<std::unique_ptr<RandomAccessStream>>
      decrypting_random_access_stream =
          streaming_aead.NewDecryptingRandomAccessStream(
              std::move(test_random_access_stream), "Some AAD");
  ASSERT_THAT(decrypting_random_access_stream.status(), IsOk());

  int chunk_size = 10;
  auto buffer = util::Buffer::New(chunk_size);
  std::string plaintext;
  int64_t position = 0;
  util::Status status = (*decrypting_random_access_stream)
                            ->PRead(position, chunk_size, buffer->get());
  while (status.ok()) {
    plaintext.append((*buffer)->get_mem_block(), (*buffer)->size());
    position += (*buffer)->size();
    status = (*decrypting_random_access_stream)
                 ->PRead(position, chunk_size, buffer->get());
  }
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kOutOfRange));
  plaintext.append((*buffer)->get_mem_block(), (*buffer)->size());
  EXPECT_EQ(stream_content, plaintext);
}

TEST(DummyStreamingAead, DummyDecryptingStreamPreadWithSmallerHeaderFails) {
  const int stream_size = 1024;
  std::string stream_content = subtle::Random::GetRandomBytes(stream_size);

  auto ostream = std::make_unique<std::ostringstream>();
  auto output_stream =
      std::make_unique<util::OstreamOutputStream>(std::move(ostream));

  constexpr absl::string_view kStreamingAeadName = "Some AEAD";
  constexpr absl::string_view kStreamingAeadAad = "Some associated data";

  DummyStreamingAead streaming_aead(kStreamingAeadName);
  util::StatusOr<std::unique_ptr<OutputStream>> encrypting_output_stream =
      streaming_aead.NewEncryptingStream(std::move(output_stream),
                                         kStreamingAeadAad);
  ASSERT_THAT(encrypting_output_stream.status(), IsOk());
  ASSERT_THAT(subtle::test::WriteToStream(
                  encrypting_output_stream.value().get(), stream_content),
              IsOk());
  // Stream content size is too small; DummyDecryptingStream expects
  // absl::StrCat(kStreamingAeadName, kStreamingAeadAad).
  std::string ciphertext = "Invalid header";
  auto test_random_access_stream =
      std::make_unique<TestRandomAccessStream>(ciphertext);
  util::StatusOr<std::unique_ptr<RandomAccessStream>>
      decrypting_random_access_stream =
          streaming_aead.NewDecryptingRandomAccessStream(
              std::move(test_random_access_stream), kStreamingAeadAad);
  ASSERT_THAT(decrypting_random_access_stream.status(), IsOk());

  int chunk_size = 10;
  auto buffer = util::Buffer::New(chunk_size);
  EXPECT_THAT(
      (*decrypting_random_access_stream)
          ->PRead(/*position=*/0, chunk_size, buffer->get()),
      StatusIs(absl::StatusCode::kInvalidArgument, "Could not read header"));
  EXPECT_THAT(
      (*decrypting_random_access_stream)
          ->PRead(/*position=*/0, chunk_size, buffer->get()),
      StatusIs(absl::StatusCode::kInvalidArgument, "Could not read header"));
  EXPECT_THAT(
      (*decrypting_random_access_stream)->size().status(),
      StatusIs(absl::StatusCode::kInvalidArgument, "Could not read header"));
}

TEST(DummyStreamingAead, DummyDecryptingStreamPreadWithCorruptedAadFails) {
  const int stream_size = 1024;
  std::string stream_content = subtle::Random::GetRandomBytes(stream_size);

  auto ostream = std::make_unique<std::ostringstream>();
  auto string_stream_buffer = ostream->rdbuf();
  auto output_stream =
      std::make_unique<util::OstreamOutputStream>(std::move(ostream));

  constexpr absl::string_view kStreamingAeadName = "Some AEAD";
  constexpr absl::string_view kStreamingAeadAad = "Some associated data";

  DummyStreamingAead streaming_aead(kStreamingAeadName);
  util::StatusOr<std::unique_ptr<OutputStream>> encrypting_output_stream =
      streaming_aead.NewEncryptingStream(std::move(output_stream),
                                         kStreamingAeadAad);
  ASSERT_THAT(encrypting_output_stream.status(), IsOk());
  ASSERT_THAT(subtle::test::WriteToStream(
                  encrypting_output_stream.value().get(), stream_content),
              IsOk());
  // Invalid associated data.
  std::string ciphertext = string_stream_buffer->str();
  auto test_random_access_stream =
      std::make_unique<TestRandomAccessStream>(ciphertext);
  util::StatusOr<std::unique_ptr<RandomAccessStream>>
      decrypting_random_access_stream =
          streaming_aead.NewDecryptingRandomAccessStream(
              std::move(test_random_access_stream), "Some wrong AAD");
  ASSERT_THAT(decrypting_random_access_stream.status(), IsOk());

  int chunk_size = 10;
  auto buffer = util::Buffer::New(chunk_size);
  EXPECT_THAT((*decrypting_random_access_stream)
                  ->PRead(/*position=*/0, chunk_size, buffer->get()),
              StatusIs(absl::StatusCode::kInvalidArgument, "Corrupted header"));
  EXPECT_THAT((*decrypting_random_access_stream)
                  ->PRead(/*position=*/0, chunk_size, buffer->get()),
              StatusIs(absl::StatusCode::kInvalidArgument, "Corrupted header"));
  EXPECT_THAT((*decrypting_random_access_stream)->size().status(),
              StatusIs(absl::StatusCode::kInvalidArgument, "Corrupted header"));
}

}  // namespace
}  // namespace test
}  // namespace tink
}  // namespace crypto
