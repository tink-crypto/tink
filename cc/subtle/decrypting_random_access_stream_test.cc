// Copyright 2019 Google Inc.
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

#include "tink/subtle/decrypting_random_access_stream.h"

#include <algorithm>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/output_stream.h"
#include "tink/random_access_stream.h"
#include "tink/streaming_aead.h"
#include "tink/subtle/random.h"
#include "tink/subtle/test_util.h"
#include "tink/util/file_random_access_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using crypto::tink::subtle::test::DummyStreamingAead;
using crypto::tink::subtle::test::DummyStreamSegmentDecrypter;
using crypto::tink::test::GetTestFileDescriptor;
using crypto::tink::test::IsOk;
using crypto::tink::test::StatusIs;
using subtle::test::WriteToStream;
using testing::HasSubstr;

// A dummy RandomAccessStream that fakes its size.
class DummyRandomAccessStream : public RandomAccessStream {
 public:
  explicit DummyRandomAccessStream(int64_t size, int ct_offset)
      : size_(size), ct_offset_(ct_offset) {}

  crypto::tink::util::Status PRead(
      int64_t position, int count,
      crypto::tink::util::Buffer* dest_buffer) override {
    if (position == ct_offset_) {
      // Someone attempts to read the header, return the same dummy value that
      // DummyStreamSegmentDecrypter expects.
      auto status = dest_buffer->set_size(count);
      if (!status.ok()) return status;
      std::memset(dest_buffer->get_mem_block(), 'h', count);
    }
    return util::OkStatus();
  }

  crypto::tink::util::StatusOr<int64_t> size() override { return size_; }

 private:
  int64_t size_;
  int ct_offset_;
};

// Creates a RandomAccessStream with the specified contents.
std::unique_ptr<RandomAccessStream> GetRandomAccessStream(
    absl::string_view contents) {
  static int index = 1;
  std::string filename = absl::StrCat("stream_data_file_", index, ".txt");
  index++;
  int input_fd = GetTestFileDescriptor(filename, contents);
  return {absl::make_unique<util::FileRandomAccessStream>(input_fd)};
}

// Returns a ciphertext resulting from encryption of 'pt' with 'aad' as
// associated data, using 'saead'.
std::string GetCiphertext(StreamingAead* saead, absl::string_view pt,
                          absl::string_view aad, int ct_offset) {
  // Prepare ciphertext destination stream.
  auto ct_stream = absl::make_unique<std::stringstream>();
  // Write ct_offset 'o'-characters for the ciphertext offset.
  *ct_stream << std::string(ct_offset, 'o');
  // A reference to the ciphertext buffer.
  auto ct_buf = ct_stream->rdbuf();
  std::unique_ptr<OutputStream> ct_destination(
      absl::make_unique<util::OstreamOutputStream>(std::move(ct_stream)));

  // Compute the ciphertext.
  auto enc_stream_result =
      saead->NewEncryptingStream(std::move(ct_destination), aad);
  EXPECT_THAT(enc_stream_result.status(), IsOk());
  EXPECT_THAT(WriteToStream(enc_stream_result.ValueOrDie().get(), pt), IsOk());

  return ct_buf->str();
}

// Creates an RandomAccessStream that contains ciphertext resulting
// from encryption of 'pt' with 'aad' as associated data, using 'saead'.
std::unique_ptr<RandomAccessStream> GetCiphertextSource(StreamingAead* saead,
                                                        absl::string_view pt,
                                                        absl::string_view aad,
                                                        int ct_offset) {
  return GetRandomAccessStream(GetCiphertext(saead, pt, aad, ct_offset));
}

// Reads the entire 'ra_stream', until no more bytes can be read,
// and puts the read bytes into 'contents'.
// Returns the status of the last ra_stream->PRead()-operation.
util::Status ReadAll(RandomAccessStream* ra_stream, std::string* contents) {
  int chunk_size = 42;
  contents->clear();
  auto buffer = std::move(util::Buffer::New(chunk_size).ValueOrDie());
  int64_t position = 0;
  auto status = util::OkStatus();
  while (status.ok()) {
    status = ra_stream->PRead(position, chunk_size, buffer.get());
    contents->append(buffer->get_mem_block(), buffer->size());
    position = contents->size();
  }
  return status;
}

TEST(DecryptingRandomAccessStreamTest, NegativeCiphertextOffset) {
  int pt_segment_size = 100;
  int header_size = 20;
  int ct_offset = -1;
  auto seg_decrypter = absl::make_unique<DummyStreamSegmentDecrypter>(
      pt_segment_size, header_size, ct_offset);
  int64_t ciphertext_size = 100;

  EXPECT_THAT(
      DecryptingRandomAccessStream::New(
          std::move(seg_decrypter), absl::make_unique<DummyRandomAccessStream>(
                                        ciphertext_size, ct_offset))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("The ciphertext offset must be non-negative")));
}

TEST(DecryptingRandomAccessStreamTest,
     SizeOfFirstSegmentIsSmallerOrEqualToZero) {
  int header_size = 20;
  int ct_offset = 0;
  // Make pt_segment_size equal to ct_offset + header_size. This means size of
  // the first segment is zero.
  int pt_segment_size = ct_offset + header_size;
  auto seg_decrypter = absl::make_unique<DummyStreamSegmentDecrypter>(
      pt_segment_size, header_size, ct_offset);
  int64_t ciphertext_size = 100;

  EXPECT_THAT(
      DecryptingRandomAccessStream::New(
          std::move(seg_decrypter), absl::make_unique<DummyRandomAccessStream>(
                                        ciphertext_size, ct_offset))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("greater than 0")));
}

TEST(DecryptingRandomAccessStreamTest, TooManySegments) {
  int header_size = 1;
  int ct_offset = 0;
  // Use a valid pt_segment_size which is larger than ct_offset + header_size.
  int pt_segment_size = ct_offset + header_size + 1;
  auto seg_decrypter = absl::make_unique<DummyStreamSegmentDecrypter>(
      pt_segment_size, header_size, ct_offset);

  // Use an invalid segment_count larger than 2^32.
  int64_t segment_count =
      static_cast<int64_t>(std::numeric_limits<uint32_t>::max()) + 2;
  // Based on this calculation:
  // segment_count = ciphertext_size / ciphertext_segment_size
  // -> ciphertext_size = segment_count * ciphertext_segment_size
  int64_t ciphertext_size =
      segment_count * seg_decrypter->get_ciphertext_segment_size();
  auto dec_stream_result = DecryptingRandomAccessStream::New(
      std::move(seg_decrypter),
      absl::make_unique<DummyRandomAccessStream>(ciphertext_size, ct_offset));
  EXPECT_THAT(dec_stream_result.status(), IsOk());
  auto dec_stream = std::move(dec_stream_result.ValueOrDie());

  auto result = dec_stream->size();
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
  EXPECT_THAT(std::string(result.status().message()),
              HasSubstr("too many segments"));
}

TEST(DecryptingRandomAccessStreamTest, BasicDecryption) {
  for (int pt_size : {1, 5, 20, 42, 100, 1000, 10000}) {
    std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
    for (int pt_segment_size : {50, 100, 123}) {
      for (int header_size : {5, 10, 15}) {
        for (int ct_offset : {0, 1, 5, 12}) {
          SCOPED_TRACE(absl::StrCat(
              "pt_size = ", pt_size, ", pt_segment_size = ", pt_segment_size,
              ", header_size = ", header_size, ", ct_offset = ", ct_offset));
          DummyStreamingAead saead(pt_segment_size, header_size, ct_offset);
          // Pre-compute the ciphertext.
          auto ciphertext =
              GetCiphertextSource(&saead, plaintext, "some aad", ct_offset);
          // Check the decryption of the pre-computed ciphertext.
          auto seg_decrypter = absl::make_unique<DummyStreamSegmentDecrypter>(
              pt_segment_size, header_size, ct_offset);
          auto dec_stream_result = DecryptingRandomAccessStream::New(
              std::move(seg_decrypter), std::move(ciphertext));
          EXPECT_THAT(dec_stream_result.status(), IsOk());
          auto dec_stream = std::move(dec_stream_result.ValueOrDie());
          EXPECT_EQ(pt_size, dec_stream->size().ValueOrDie());
          std::string decrypted;
          auto status = ReadAll(dec_stream.get(), &decrypted);
          EXPECT_THAT(status, StatusIs(absl::StatusCode::kOutOfRange,
                                       HasSubstr("EOF")));
          EXPECT_EQ(plaintext, decrypted);
        }
      }
    }
  }
}

TEST(DecryptingRandomAccessStreamTest, SelectiveDecryption) {
  for (int pt_size : {1, 20, 42, 100, 1000, 10000}) {
    std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
    for (int pt_segment_size : {50, 100, 200}) {
      for (int header_size : {5, 10, 20}) {
        for (int ct_offset : {0, 1, 10}) {
          SCOPED_TRACE(absl::StrCat(
              "pt_size = ", pt_size, ", pt_segment_size = ", pt_segment_size,
              ", header_size = ", header_size, ", ct_offset = ", ct_offset));
          DummyStreamingAead saead(pt_segment_size, header_size, ct_offset);
          // Pre-compute the ciphertext.
          auto ciphertext =
              GetCiphertextSource(&saead, plaintext, "some aad", ct_offset);
          // Check the decryption of the pre-computed ciphertext.
          auto seg_decrypter = absl::make_unique<DummyStreamSegmentDecrypter>(
              pt_segment_size, header_size, ct_offset);
          auto dec_stream_result = DecryptingRandomAccessStream::New(
              std::move(seg_decrypter), std::move(ciphertext));
          EXPECT_THAT(dec_stream_result.status(), IsOk());
          auto dec_stream = std::move(dec_stream_result.ValueOrDie());
          for (int position : {0, 1, 2, pt_size / 2, pt_size - 1}) {
            for (int chunk_size : {1, pt_size / 2, pt_size}) {
              SCOPED_TRACE(absl::StrCat("position = ", position,
                                        ", chunk_size = ", chunk_size));
              auto buffer = std::move(
                  util::Buffer::New(std::max(chunk_size, 1)).ValueOrDie());
              auto status =
                  dec_stream->PRead(position, chunk_size, buffer.get());
              if (position <= pt_size) {
                EXPECT_TRUE(status.ok() ||
                            status.code() == absl::StatusCode::kOutOfRange);
              } else {
                EXPECT_THAT(status,
                            StatusIs(absl::StatusCode::kInvalidArgument));
              }
              EXPECT_EQ(std::min(chunk_size, std::max(pt_size - position, 0)),
                        buffer->size());
              EXPECT_EQ(0,
                        std::memcmp(plaintext.data() + position,
                                    buffer->get_mem_block(), buffer->size()));
            }
          }
        }
      }
    }
  }
}

TEST(DecryptingRandomAccessStreamTest, TruncatedCiphertextDecryption) {
  for (int pt_size : {100, 200, 1000}) {
    std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
    for (int pt_segment_size : {50, 70}) {
      for (int header_size : {5, 10, 20}) {
        for (int ct_offset : {0, 1, 10}) {
          SCOPED_TRACE(absl::StrCat(
              "pt_size = ", pt_size, ", pt_segment_size = ", pt_segment_size,
              ", header_size = ", header_size, ", ct_offset = ", ct_offset));
          DummyStreamingAead saead(pt_segment_size, header_size, ct_offset);
          // Pre-compute the ciphertext.
          auto ct = GetCiphertext(&saead, plaintext, "some aad", ct_offset);
          // Check the decryption of a truncated ciphertext.
          auto seg_decrypter = absl::make_unique<DummyStreamSegmentDecrypter>(
              pt_segment_size, header_size, ct_offset);
          for (int trunc_ct_size : {header_size + ct_offset,
                  static_cast<int>(ct.size()) - 1,
                  static_cast<int>(ct.size()) - pt_segment_size,
                  static_cast<int>(ct.size())
                      - seg_decrypter->get_ciphertext_segment_size()}) {
            for (int chunk_size : {pt_size}) {
              SCOPED_TRACE(absl::StrCat("ct_size = ", ct.size(),
                                        ", trunc_ct_size = ", trunc_ct_size,
                                        ", chunk_size = ", chunk_size));
              auto trunc_ct =
                  GetRandomAccessStream(ct.substr(0, trunc_ct_size));
              int position = 0;
              auto per_stream_seg_decrypter =
                  absl::make_unique<DummyStreamSegmentDecrypter>(
                      pt_segment_size, header_size, ct_offset);
              auto dec_stream_result = DecryptingRandomAccessStream::New(
                  std::move(per_stream_seg_decrypter), std::move(trunc_ct));
              EXPECT_THAT(dec_stream_result.status(), IsOk());
              auto dec_stream = std::move(dec_stream_result.ValueOrDie());
              auto buffer =
                  std::move(util::Buffer::New(chunk_size).ValueOrDie());
              auto status =
                  dec_stream->PRead(position, chunk_size, buffer.get());
              EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
            }
          }
        }
      }
    }
  }
}

TEST(DecryptingRandomAccessStreamTest, OutOfRangeDecryption) {
  for (int pt_size : {0, 20, 42, 100, 1000, 10000}) {
    std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
    for (int pt_segment_size : {50, 100, 123}) {
      for (int header_size : {5, 10, 20}) {
        SCOPED_TRACE(absl::StrCat("pt_size = ", pt_size,
                                  ", pt_segment_size = ", pt_segment_size,
                                  ", header_size = ", header_size));
        int ct_offset = 0;
        DummyStreamingAead saead(pt_segment_size, header_size, ct_offset);
        // Pre-compute the ciphertext.
        auto ciphertext =
            GetCiphertextSource(&saead, plaintext, "some aad", ct_offset);
        // Check the decryption of the pre-computed ciphertext.
        auto seg_decrypter = absl::make_unique<DummyStreamSegmentDecrypter>(
            pt_segment_size, header_size, ct_offset);
        auto dec_stream_result = DecryptingRandomAccessStream::New(
            std::move(seg_decrypter), std::move(ciphertext));
        EXPECT_THAT(dec_stream_result.status(), IsOk());
        auto dec_stream = std::move(dec_stream_result.ValueOrDie());
        int chunk_size = 1;
        auto buffer = std::move(util::Buffer::New(chunk_size).ValueOrDie());
        int position = pt_size;
        // Negative chunk size.
        auto status = dec_stream->PRead(position, -1, buffer.get());
        EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));

        // Negative position.
        status = dec_stream->PRead(-1, chunk_size, buffer.get());
        EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));

        // Reading at EOF.
        status = dec_stream->PRead(position, chunk_size, buffer.get());
        EXPECT_THAT(status, StatusIs(absl::StatusCode::kOutOfRange));

        // Reading past EOF.
        status = dec_stream->PRead(position + 1 , chunk_size, buffer.get());
        EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
      }
    }
  }
}

TEST(DecryptingRandomAccessStreamTest, WrongCiphertext) {
  int pt_segment_size = 42;
  int header_size = 10;
  int ct_offset = 0;
  for (int ct_size : {0, 10, 100}) {
    SCOPED_TRACE(absl::StrCat("ct_size = ", ct_size));
    // Try decrypting a wrong ciphertext.
    auto wrong_ct =
        GetRandomAccessStream(subtle::Random::GetRandomBytes(ct_size));
    auto seg_decrypter = absl::make_unique<DummyStreamSegmentDecrypter>(
        pt_segment_size, header_size, ct_offset);
    auto dec_stream_result = DecryptingRandomAccessStream::New(
        std::move(seg_decrypter), std::move(wrong_ct));
    EXPECT_THAT(dec_stream_result.status(), IsOk());
    auto dec_stream = std::move(dec_stream_result.ValueOrDie());
    std::string decrypted;
    int chunk_size = 1;
    int position = 0;
    auto buffer = std::move(util::Buffer::New(chunk_size).ValueOrDie());
    auto status = dec_stream->PRead(position, chunk_size, buffer.get());
    EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(DecryptingRandomAccessStreamTest, NullSegmentDecrypter) {
  auto ct_stream = GetRandomAccessStream("some ciphertext contents");
  auto dec_stream_result =
      DecryptingRandomAccessStream::New(nullptr, std::move(ct_stream));
  EXPECT_THAT(dec_stream_result.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("segment_decrypter must be non-null")));
}

TEST(DecryptingRandomAccessStreamTest, NullCiphertextSource) {
  int pt_segment_size = 42;
  int header_size = 10;
  int ct_offset = 0;
  auto seg_decrypter = absl::make_unique<DummyStreamSegmentDecrypter>(
      pt_segment_size, header_size, ct_offset);
  auto dec_stream_result =
      DecryptingRandomAccessStream::New(std::move(seg_decrypter), nullptr);
  EXPECT_THAT(dec_stream_result.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("cipertext_source must be non-null")));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
