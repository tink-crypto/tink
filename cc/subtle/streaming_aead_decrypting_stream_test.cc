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

#include "tink/subtle/streaming_aead_decrypting_stream.h"

#include <sstream>
#include <vector>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/input_stream.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/subtle/random.h"
#include "tink/subtle/test_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

using crypto::tink::InputStream;
using crypto::tink::subtle::test::DummyStreamSegmentDecrypter;
using crypto::tink::subtle::test::DummyStreamSegmentEncrypter;
using crypto::tink::util::IstreamInputStream;

namespace crypto {
namespace tink {
namespace subtle {
namespace {

// References to objects used for test validation.
// The objects pointed to are not owned by this structure.
struct ValidationRefs {
  DummyStreamSegmentDecrypter* seg_dec;  // segment decrypter
};

// A helper for creating StreamingAeadDecryptingStream together
// with references to internal objects, used for test validation.
std::unique_ptr<InputStream> GetDecryptingStream(
    int pt_segment_size, int header_size, int ct_offset,
    absl::string_view ciphertext, ValidationRefs* refs) {
  // Prepare ciphertext source stream.
  auto ct_stream =
      absl::make_unique<std::stringstream>(std::string(ciphertext));
  std::unique_ptr<InputStream> ct_source(
      absl::make_unique<IstreamInputStream>(std::move(ct_stream)));
  auto seg_dec = absl::make_unique<DummyStreamSegmentDecrypter>(
          pt_segment_size, header_size, ct_offset);
  // A reference to the segment decrypter, for later validation.
  refs->seg_dec = seg_dec.get();
  auto dec_stream = std::move(StreamingAeadDecryptingStream::New(
      std::move(seg_dec), std::move(ct_source)).ValueOrDie());
  EXPECT_EQ(0, dec_stream->Position());
  return dec_stream;
}


class StreamingAeadDecryptingStreamTest : public ::testing::Test {
};

TEST_F(StreamingAeadDecryptingStreamTest, WritingStreams) {
  std::vector<int> pt_sizes = {0, 10, 100, 1000, 10000, 100000, 1000000};
  std::vector<int> pt_segment_sizes = {64, 100, 128, 1000, 1024};
  std::vector<int> header_sizes = {5, 10, 32};
  std::vector<int> ct_offsets = {0, 1, 5, 15};
  for (auto pt_size : pt_sizes) {
    for (auto pt_segment_size : pt_segment_sizes) {
      for (auto header_size : header_sizes) {
        for (auto ct_offset : ct_offsets) {
          SCOPED_TRACE(absl::StrCat("pt_size = ", pt_size,
                                    ", pt_segment_size = ", pt_segment_size,
                                    ", header_size = ", header_size,
                                    ", ct_offset = ", ct_offset));
          // Get a decrypting stream.
          std::string pt = Random::GetRandomBytes(pt_size);
          DummyStreamSegmentEncrypter seg_enc(pt_segment_size, header_size,
              ct_offset);
          std::string ct = seg_enc.GenerateCiphertext(pt);

          ValidationRefs refs;
          auto dec_stream = GetDecryptingStream(pt_segment_size, header_size,
              ct_offset, ct, &refs);

          // First buffer returned by Next();
          const void* buffer;
          auto next_result = dec_stream->Next(&buffer);
          EXPECT_TRUE(next_result.ok()) << next_result.status();
          int buffer_size = next_result.ValueOrDie();
          int exp_buffer_size = pt_segment_size - (header_size + ct_offset);
          if (exp_buffer_size > pt_size) exp_buffer_size = pt_size;
          EXPECT_EQ(exp_buffer_size, buffer_size);
          EXPECT_EQ(buffer_size, dec_stream->Position());

          // Backup the entire first buffer.
          dec_stream->BackUp(buffer_size);
          EXPECT_EQ(0, dec_stream->Position());

          // Read the entire plaintext to the stream.
          std::string decrypted;
          auto status = test::ReadFromStream(dec_stream.get(), &decrypted);
          EXPECT_TRUE(status.ok()) << status;
          EXPECT_EQ(dec_stream->Position(), pt.size());
          EXPECT_EQ(pt, decrypted);
        }
      }
    }
  }
}

TEST_F(StreamingAeadDecryptingStreamTest, EmptyCiphertext) {
  int pt_segment_size = 512;
  int header_size = 64;

  // Get a decrypting stream.
  ValidationRefs refs;
  auto dec_stream = GetDecryptingStream(pt_segment_size, header_size,
      /* ct_offset = */ 0, /* ciphertext = */ "", &refs);

  // First buffer returned by Next();
  const void* buffer;
  auto next_result = dec_stream->Next(&buffer);
  EXPECT_FALSE(next_result.ok());
  EXPECT_EQ(next_result.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "Could not read stream header",
                      std::string(next_result.status().message()));
}

TEST_F(StreamingAeadDecryptingStreamTest, InvalidStreamHeader) {
  int pt_segment_size = 512;
  int header_size = 64;

  // Get a decrypting stream.
  ValidationRefs refs;
  auto dec_stream = GetDecryptingStream(pt_segment_size, header_size,
                                        /* ct_offset = */ 0,
                                        std::string(header_size, 'a'), &refs);

  // First buffer returned by Next();
  const void* buffer;
  auto next_result = dec_stream->Next(&buffer);
  EXPECT_FALSE(next_result.ok());
  EXPECT_EQ(next_result.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "Invalid stream header",
                      std::string(next_result.status().message()));
}

TEST_F(StreamingAeadDecryptingStreamTest, TruncatedLastSegment) {
  int pt_segment_size = 120;
  int pt_size = 500;
  int header_size = 64;

  // Get a decrypting stream.
  std::string pt = Random::GetRandomBytes(pt_size);
  DummyStreamSegmentEncrypter seg_enc(pt_segment_size, header_size,
      /* ct_offset = */ 0);
  std::string ct = seg_enc.GenerateCiphertext(pt);

  ValidationRefs refs;
  auto dec_stream = GetDecryptingStream(pt_segment_size, header_size,
      /* ct_offset = */ 0, ct.substr(0, ct.size()-2), &refs);

  // First buffer returned by Next();
  std::string decrypted;
  auto status = test::ReadFromStream(dec_stream.get(), &decrypted);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "unexpected last-segment marker",
                      std::string(status.message()));
}


TEST_F(StreamingAeadDecryptingStreamTest, OneSegmentPlaintext) {
  int pt_segment_size = 512;
  int header_size = 64;

  // Get a decrypting stream.
  std::string pt = Random::GetRandomBytes(pt_segment_size - header_size);
  DummyStreamSegmentEncrypter seg_enc(pt_segment_size, header_size,
      /* ct_offset = */ 0);
  std::string ct = seg_enc.GenerateCiphertext(pt);
  EXPECT_EQ(seg_enc.get_ciphertext_segment_size(), ct.size());

  ValidationRefs refs;
  auto dec_stream = GetDecryptingStream(pt_segment_size, header_size,
      /* ct_offset = */ 0, ct, &refs);

  // Get the first segment.
  const void* buffer;
  auto next_result = dec_stream->Next(&buffer);
  int buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, dec_stream->Position());
  EXPECT_EQ(pt,
            std::string(reinterpret_cast<const char*>(buffer), buffer_size));

  // Try getting another segment.
  next_result = dec_stream->Next(&buffer);
  EXPECT_FALSE(next_result.ok());
  EXPECT_EQ(absl::StatusCode::kOutOfRange, next_result.status().code());
}


TEST_F(StreamingAeadDecryptingStreamTest, OneSegmentAndOneBytePlaintext) {
  int pt_segment_size = 512;
  int header_size = 64;

  // Get a decrypting stream.
  std::string pt = Random::GetRandomBytes(pt_segment_size - header_size + 1);
  DummyStreamSegmentEncrypter seg_enc(pt_segment_size, header_size,
      /* ct_offset = */ 0);
  std::string ct = seg_enc.GenerateCiphertext(pt);
  EXPECT_EQ(seg_enc.get_ciphertext_segment_size() +
            DummyStreamSegmentEncrypter::kSegmentTagSize + 1,
            ct.size());

  ValidationRefs refs;
  auto dec_stream = GetDecryptingStream(pt_segment_size, header_size,
      /* ct_offset = */ 0, ct, &refs);

  // Get the first segment.
  const void* buffer;
  auto next_result = dec_stream->Next(&buffer);
  int buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, dec_stream->Position());
  EXPECT_EQ(pt.substr(0, buffer_size),
            std::string(reinterpret_cast<const char*>(buffer), buffer_size));

  // Get the second segment.
  next_result = dec_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(1, next_result.ValueOrDie());
  EXPECT_EQ(pt.size(), dec_stream->Position());
  EXPECT_EQ(pt.at(pt.size()-1), *(reinterpret_cast<const char*>(buffer)));

  // Try getting another segment.
  next_result = dec_stream->Next(&buffer);
  EXPECT_FALSE(next_result.ok());
  EXPECT_EQ(absl::StatusCode::kOutOfRange, next_result.status().code());
}

TEST_F(StreamingAeadDecryptingStreamTest, NextAfterBackUp) {
  int pt_segment_size = 97;
  int pt_size = 334;
  int header_size = 30;

  // Get a decrypting stream.
  std::string pt = Random::GetRandomBytes(pt_size);
  DummyStreamSegmentEncrypter seg_enc(pt_segment_size, header_size,
      /* ct_offset = */ 0);
  std::string ct = seg_enc.GenerateCiphertext(pt);
  ValidationRefs refs;
  auto dec_stream = GetDecryptingStream(pt_segment_size, header_size,
      /* ct_offset = */ 0, ct, &refs);

  // Get the first segment.
  const void* buffer;
  auto next_result = dec_stream->Next(&buffer);
  int buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, dec_stream->Position());
  EXPECT_EQ(pt.substr(0, buffer_size),
            std::string(reinterpret_cast<const char*>(buffer), buffer_size));
  std::string decrypted_first_segment(reinterpret_cast<const char*>(buffer),
                                      buffer_size);

  // Backup part of the first segment, and call Next again.
  int backup_size = buffer_size / 2;
  dec_stream->BackUp(backup_size);
  EXPECT_EQ(buffer_size - backup_size, dec_stream->Position());
  next_result = dec_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(backup_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, dec_stream->Position());
  EXPECT_EQ(pt.substr(buffer_size - backup_size, backup_size),
            std::string(reinterpret_cast<const char*>(buffer), backup_size));

  // Backup a smaller part of the first segment, and call Next again.
  int backup2_size = buffer_size / 4;
  dec_stream->BackUp(backup2_size);
  EXPECT_EQ(buffer_size - backup2_size, dec_stream->Position());
  next_result = dec_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(backup2_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, dec_stream->Position());
  EXPECT_EQ(pt.substr(buffer_size - backup2_size, backup2_size),
            std::string(reinterpret_cast<const char*>(buffer), backup2_size));

  // Read the stream to the end.
  std::string decrypted_rest;
  auto status = test::ReadFromStream(dec_stream.get(), &decrypted_rest);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(pt_size, dec_stream->Position());
  EXPECT_EQ(pt, (decrypted_first_segment + decrypted_rest));
}

TEST_F(StreamingAeadDecryptingStreamTest, BackupAndPosition) {
  int pt_segment_size = 555;
  int pt_size = 2313;
  int header_size = 33;

  // Get a decrypting stream.
  std::string pt = Random::GetRandomBytes(pt_size);
  DummyStreamSegmentEncrypter seg_enc(pt_segment_size, header_size,
      /* ct_offset = */ 0);
  std::string ct = seg_enc.GenerateCiphertext(pt);
  ValidationRefs refs;
  auto dec_stream = GetDecryptingStream(pt_segment_size, header_size,
      /* ct_offset = */ 0, ct, &refs);

  // The first segment.
  const void* buffer;
  auto next_result = dec_stream->Next(&buffer);
  int buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, dec_stream->Position());
  std::string decrypted_first_segment(reinterpret_cast<const char*>(buffer),
                                      buffer_size);

  // BackUp several times, but in total fewer bytes than returned by Next().
  std::vector<int> backup_sizes = {0, 1, 5, 0, 10, 78, -42, 60, 120, -120};
  int total_backup_size = 0;
  for (auto backup_size : backup_sizes) {
    dec_stream->BackUp(backup_size);
    total_backup_size += std::max(0, backup_size);
    EXPECT_EQ(buffer_size - total_backup_size, dec_stream->Position());
  }
  EXPECT_LT(total_backup_size, next_result.ValueOrDie());

  // Call Next(), it should succeed (backuped bytes of 1st segment).
  next_result = dec_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(total_backup_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, dec_stream->Position());

  // BackUp() some bytes, again fewer than returned by Next().
  backup_sizes = {0, 72, -94, 37, 82};
  total_backup_size = 0;
  for (auto backup_size : backup_sizes) {
    dec_stream->BackUp(backup_size);
    total_backup_size += std::max(0, backup_size);
    EXPECT_EQ(buffer_size - total_backup_size, dec_stream->Position());
  }
  EXPECT_LT(total_backup_size, next_result.ValueOrDie());

  // Call Next(), it should succeed  (backuped bytes of 1st segment).
  next_result = dec_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(total_backup_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, dec_stream->Position());

  // Call Next() again, it should return a full block (2nd segment).
  auto prev_position = dec_stream->Position();
  buffer_size = pt_segment_size;
  next_result = dec_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(prev_position + buffer_size, dec_stream->Position());

  // BackUp a few times, with total over the returned buffer_size.
  backup_sizes = {0, 72, -100, buffer_size / 2, 200, -25, buffer_size / 2, 42};
  total_backup_size = 0;
  for (auto backup_size : backup_sizes) {
    SCOPED_TRACE(absl::StrCat("backup_size = ", backup_size,
                              ", total_backup_size = ", total_backup_size));
    dec_stream->BackUp(backup_size);
    total_backup_size = std::min(buffer_size,
                                 total_backup_size + std::max(0, backup_size));
    EXPECT_EQ(prev_position + buffer_size - total_backup_size,
              dec_stream->Position());
  }
  EXPECT_EQ(total_backup_size, buffer_size);
  EXPECT_EQ(prev_position, dec_stream->Position());

  // Call Next() again, it should return a full segment (2nd segment);
  next_result = dec_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(prev_position + buffer_size, dec_stream->Position());
  EXPECT_EQ(2 * pt_segment_size - header_size, dec_stream->Position());

  // Backup the 2nd segment again, and read the stream to the end.
  dec_stream->BackUp(buffer_size);
  EXPECT_EQ(prev_position, dec_stream->Position());
  std::string decrypted_rest;
  auto status = test::ReadFromStream(dec_stream.get(), &decrypted_rest);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(pt_size, dec_stream->Position());
  EXPECT_EQ(pt, decrypted_first_segment + decrypted_rest);
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
