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

#include "tink/subtle/streaming_aead_encrypting_stream.h"

#include <algorithm>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/output_stream.h"
#include "tink/subtle/random.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/subtle/test_util.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

using crypto::tink::OutputStream;
using crypto::tink::subtle::test::DummyStreamSegmentEncrypter;
using crypto::tink::util::OstreamOutputStream;

namespace {

// References to objects used for test validation.
// The objects pointed to are not owned by this structure.
struct ValidationRefs {
  std::stringbuf* ct_buf;  // buffer that contains the resulting ciphertext
  DummyStreamSegmentEncrypter* seg_enc;  // segment encrypter
};

// A helper for creating StreamingAeadEncryptingStream together
// with references to internal objects, used for test validation.
std::unique_ptr<OutputStream> GetEncryptingStream(
    int pt_segment_size, int header_size, int ct_offset, ValidationRefs* refs) {
  // Prepare ciphertext destination stream.
  auto ct_stream = absl::make_unique<std::stringstream>();
  // A reference to the ciphertext buffer, for later validation.
  refs->ct_buf = ct_stream->rdbuf();
  std::unique_ptr<OutputStream> ct_destination(
      absl::make_unique<OstreamOutputStream>(std::move(ct_stream)));
  auto seg_enc = absl::make_unique<DummyStreamSegmentEncrypter>(
          pt_segment_size, header_size, ct_offset);
  // A reference to the segment encrypter, for later validation.
  refs->seg_enc = seg_enc.get();
  auto enc_stream = std::move(StreamingAeadEncryptingStream::New(
                                  std::move(seg_enc), std::move(ct_destination))
                                  .value());
  EXPECT_EQ(0, enc_stream->Position());
  return enc_stream;
}


class StreamingAeadEncryptingStreamTest : public ::testing::Test {
};

TEST_F(StreamingAeadEncryptingStreamTest, WritingStreams) {
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
          // Get an encrypting stream.
          ValidationRefs refs;
          auto enc_stream = GetEncryptingStream(pt_segment_size, header_size,
              ct_offset, &refs);

          // First buffer returned by Next();
          void* buffer;
          auto next_result = enc_stream->Next(&buffer);
          EXPECT_TRUE(next_result.ok()) << next_result.status();
          int buffer_size = next_result.value();
          EXPECT_EQ(pt_segment_size - (header_size + ct_offset), buffer_size);
          EXPECT_EQ(buffer_size, enc_stream->Position());

          // Backup the entire first buffer.
          enc_stream->BackUp(buffer_size);
          EXPECT_EQ(0, enc_stream->Position());

          // Write plaintext to the stream, and close the stream.
          std::string pt = Random::GetRandomBytes(pt_size);
          auto status = test::WriteToStream(enc_stream.get(), pt);
          EXPECT_TRUE(status.ok()) << status;
          EXPECT_EQ(enc_stream->Position(), pt.size());
          EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
                    refs.ct_buf->str().size());
          auto exp_ciphertext = refs.seg_enc->GenerateCiphertext(pt);
          EXPECT_EQ(exp_ciphertext.size(), refs.ct_buf->str().size());
          EXPECT_EQ(exp_ciphertext, refs.ct_buf->str());

          // Try closing the stream again.
          status = enc_stream->Close();
          EXPECT_FALSE(status.ok());
          EXPECT_EQ(absl::StatusCode::kFailedPrecondition, status.code());
        }
      }
    }
  }
}

TEST_F(StreamingAeadEncryptingStreamTest, EmptyPlaintext) {
  int pt_segment_size = 512;
  int header_size = 64;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ 0, &refs);

  // Close the stream.
  auto close_status = enc_stream->Close();
  EXPECT_TRUE(close_status.ok()) << close_status;
  EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
            refs.ct_buf->str().size());
  // Ciphertext contains only the header and an "empty" first segment.
  EXPECT_EQ(header_size + DummyStreamSegmentEncrypter::kSegmentTagSize,
            refs.ct_buf->str().size());
  // The last segment is marked as such.
  EXPECT_EQ(DummyStreamSegmentEncrypter::kLastSegment,
            refs.ct_buf->str().back());

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(absl::StatusCode::kFailedPrecondition, close_status.code());
}

TEST_F(StreamingAeadEncryptingStreamTest, EmptyPlaintextWithBackup) {
  int pt_segment_size = 512;
  int header_size = 64;
  void* buffer;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ 0, &refs);

  // Get the first segment.
  auto next_result = enc_stream->Next(&buffer);
  int buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.value());
  EXPECT_EQ(buffer_size, enc_stream->Position());

  // Backup the entire segment, and close the stream.
  enc_stream->BackUp(buffer_size);
  EXPECT_EQ(0, enc_stream->Position());
  auto close_status = enc_stream->Close();
  EXPECT_TRUE(close_status.ok()) << close_status;
  EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
            refs.ct_buf->str().size());
  // Ciphertext contains only the header and an "empty" first segment.
  EXPECT_EQ(header_size + DummyStreamSegmentEncrypter::kSegmentTagSize,
            refs.ct_buf->str().size());
  // The last segment is marked as such.
  EXPECT_EQ(DummyStreamSegmentEncrypter::kLastSegment,
            refs.ct_buf->str().back());

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(absl::StatusCode::kFailedPrecondition, close_status.code());
}

TEST_F(StreamingAeadEncryptingStreamTest, OneSegmentPlaintext) {
  int pt_segment_size = 512;
  int header_size = 64;
  void* buffer;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ 0, &refs);

  // Get the first segment, and close the stream.
  auto next_result = enc_stream->Next(&buffer);
  int buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.value());
  EXPECT_EQ(buffer_size, enc_stream->Position());
  auto close_status = enc_stream->Close();
  EXPECT_TRUE(close_status.ok()) << close_status;
  EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
            refs.ct_buf->str().size());
  // Ciphertext contains only header and a full first segment.
  EXPECT_EQ(pt_segment_size + DummyStreamSegmentEncrypter::kSegmentTagSize,
            refs.ct_buf->str().size());
  // The last segment is marked as such.
  EXPECT_EQ(DummyStreamSegmentEncrypter::kLastSegment,
            refs.ct_buf->str().back());

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(absl::StatusCode::kFailedPrecondition, close_status.code());
}

TEST_F(StreamingAeadEncryptingStreamTest, NextAfterBackup) {
  int pt_segment_size = 512;
  int part1_size = 123;
  int part2_size = 74;
  int header_size = 64;
  void* buffer;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ 0, &refs);

  // Get the first segment.
  auto next_result = enc_stream->Next(&buffer);
  int buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.value());
  EXPECT_EQ(buffer_size, enc_stream->Position());

  // Backup so that only part1_size bytes are written.
  enc_stream->BackUp(buffer_size - part1_size);
  EXPECT_EQ(part1_size, enc_stream->Position());

  // Get backed up space.
  void* backedup_buffer;
  next_result = enc_stream->Next(&backedup_buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size - part1_size, next_result.value());
  EXPECT_EQ(reinterpret_cast<uint8_t*>(buffer) + part1_size,
            reinterpret_cast<uint8_t*>(backedup_buffer));

  // Backup so again that (part1_size + part2_size) bytes are written.
  enc_stream->BackUp(buffer_size - (part1_size + part2_size));
  EXPECT_EQ(part1_size + part2_size, enc_stream->Position());

  // Get backed up space again.
  next_result = enc_stream->Next(&backedup_buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size - (part1_size + part2_size), next_result.value());
  EXPECT_EQ(reinterpret_cast<uint8_t*>(buffer) + part1_size + part2_size,
            reinterpret_cast<uint8_t*>(backedup_buffer));

  // Close the stream.
  auto close_status = enc_stream->Close();
  EXPECT_TRUE(close_status.ok()) << close_status;
}

TEST_F(StreamingAeadEncryptingStreamTest, OneSegmentPlaintextWithBackup) {
  int pt_segment_size = 512;
  int pt_size = 200;
  int header_size = 64;
  void* buffer;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ 0, &refs);

  // Get the first segment.
  auto next_result = enc_stream->Next(&buffer);
  int buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.value());
  EXPECT_EQ(buffer_size, enc_stream->Position());

  // Backup so that only pt_size bytes are written, and close the stream.
  enc_stream->BackUp(buffer_size - pt_size);
  EXPECT_EQ(pt_size, enc_stream->Position());
  auto close_status = enc_stream->Close();
  EXPECT_TRUE(close_status.ok()) << close_status;
  EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
            refs.ct_buf->str().size());
  // Ciphertext contains only the header and partial first segment.
  EXPECT_EQ(
      header_size + pt_size + DummyStreamSegmentEncrypter::kSegmentTagSize,
      refs.ct_buf->str().size());
  // The last segment is marked as such.
  EXPECT_EQ(DummyStreamSegmentEncrypter::kLastSegment,
            refs.ct_buf->str().back());

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(absl::StatusCode::kFailedPrecondition, close_status.code());
}

TEST_F(StreamingAeadEncryptingStreamTest, ManySegmentsPlaintext) {
  int pt_segment_size = 512;
  int header_size = 64;
  void* buffer;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ 0, &refs);

  int seg_count = 5;
  // Get the first segment.
  auto next_result = enc_stream->Next(&buffer);
  int first_buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(first_buffer_size, next_result.value());
  EXPECT_EQ(first_buffer_size, enc_stream->Position());

  // Get remaining segments.
  for (int i = 1; i < seg_count; i++) {
    next_result = enc_stream->Next(&buffer);
    EXPECT_TRUE(next_result.ok()) << next_result.status();
    EXPECT_EQ(pt_segment_size, next_result.value());
    EXPECT_EQ(first_buffer_size + i * pt_segment_size, enc_stream->Position());
  }

  // Close the stream.
  auto close_status = enc_stream->Close();
  EXPECT_TRUE(close_status.ok()) << close_status;
  EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
            refs.ct_buf->str().size());
  // Ciphertext contains seg_count full segments.
  int ct_segment_size =
      pt_segment_size + DummyStreamSegmentEncrypter::kSegmentTagSize;
  EXPECT_EQ(refs.seg_enc->get_ciphertext_segment_size(), ct_segment_size);
  EXPECT_EQ(ct_segment_size * seg_count, refs.ct_buf->str().size());
  // The last segment is marked as such.
  EXPECT_EQ(DummyStreamSegmentEncrypter::kLastSegment,
            refs.ct_buf->str().back());
  // The previous segments are marked as not-last ones.
  for (int i = 1; i < seg_count - 1; i++) {
    EXPECT_EQ(DummyStreamSegmentEncrypter::kNotLastSegment,
              refs.ct_buf->str()[(ct_segment_size * i)-1]);
  }

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(absl::StatusCode::kFailedPrecondition, close_status.code());
}

TEST_F(StreamingAeadEncryptingStreamTest, ManySegmentsPlaintextWithBackup) {
  int pt_segment_size = 512;
  int backup_size = 100;
  int header_size = 64;
  void* buffer;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ 0, &refs);

  int seg_count = 5;
  // Get the first segment.
  auto next_result = enc_stream->Next(&buffer);
  int first_buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(first_buffer_size, next_result.value());
  EXPECT_EQ(first_buffer_size, enc_stream->Position());

  // Get remaining segments.
  for (int i = 1; i < seg_count; i++) {
    next_result = enc_stream->Next(&buffer);
    EXPECT_TRUE(next_result.ok()) << next_result.status();
    EXPECT_EQ(pt_segment_size, next_result.value());
    EXPECT_EQ(first_buffer_size + i * pt_segment_size, enc_stream->Position());
  }
  // Backup part of the last segment, and close the stream.
  enc_stream->BackUp(backup_size);
  EXPECT_EQ(first_buffer_size + (seg_count - 1) * pt_segment_size - backup_size,
            enc_stream->Position());
  auto close_status = enc_stream->Close();
  EXPECT_TRUE(close_status.ok()) << close_status;
  EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
            refs.ct_buf->str().size());
  // Ciphertext contains seg_count full segments, minus the size of the backup.
  int ct_segment_size =
      pt_segment_size + DummyStreamSegmentEncrypter::kSegmentTagSize;
  EXPECT_EQ(refs.seg_enc->get_ciphertext_segment_size(), ct_segment_size);
  EXPECT_EQ(ct_segment_size * seg_count - backup_size,
            refs.ct_buf->str().size());
  // The last segment is marked as such.
  EXPECT_EQ(DummyStreamSegmentEncrypter::kLastSegment,
            refs.ct_buf->str().back());
  // The previous segments are marked as not-last ones.
  for (int i = 1; i < seg_count - 1; i++) {
    EXPECT_EQ(DummyStreamSegmentEncrypter::kNotLastSegment,
              refs.ct_buf->str()[(ct_segment_size * i)-1]);
  }

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(absl::StatusCode::kFailedPrecondition, close_status.code());
}

TEST_F(StreamingAeadEncryptingStreamTest, ManySegmentsPlaintextWithFullBackup) {
  int pt_segment_size = 512;
  int header_size = 64;
  void* buffer;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ 0, &refs);

  int seg_count = 5;
  // Get the first segment.
  auto next_result = enc_stream->Next(&buffer);
  int first_buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(first_buffer_size, next_result.value());
  EXPECT_EQ(first_buffer_size, enc_stream->Position());

  // Get remaining segments.
  for (int i = 1; i < seg_count; i++) {
    next_result = enc_stream->Next(&buffer);
    EXPECT_TRUE(next_result.ok()) << next_result.status();
    EXPECT_EQ(pt_segment_size, next_result.value());
    EXPECT_EQ(first_buffer_size + i * pt_segment_size, enc_stream->Position());
  }
  // Backup the entire last segment, and close the stream.
  enc_stream->BackUp(pt_segment_size);
  EXPECT_EQ(first_buffer_size + (seg_count - 2) * pt_segment_size,
            enc_stream->Position());
  auto close_status = enc_stream->Close();
  EXPECT_TRUE(close_status.ok()) << close_status;
  EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
            refs.ct_buf->str().size());
  // Ciphertext contains (seg_count - 1) full segments.
  int ct_segment_size =
      pt_segment_size + DummyStreamSegmentEncrypter::kSegmentTagSize;
  EXPECT_EQ(refs.seg_enc->get_ciphertext_segment_size(), ct_segment_size);
  EXPECT_EQ(ct_segment_size * (seg_count - 1), refs.ct_buf->str().size());
  // The last segment is marked as such.
  EXPECT_EQ(DummyStreamSegmentEncrypter::kLastSegment,
            refs.ct_buf->str().back());
  // The previous segments are marked as not-last ones.
  for (int i = 1; i < seg_count - 1; i++) {
    EXPECT_EQ(DummyStreamSegmentEncrypter::kNotLastSegment,
              refs.ct_buf->str()[(ct_segment_size * i)-1]);
  }

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(absl::StatusCode::kFailedPrecondition, close_status.code());
}

TEST_F(StreamingAeadEncryptingStreamTest, BackupAndPosition) {
  int pt_segment_size = 512;
  int header_size = 64;
  void* buffer;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ 0, &refs);

  // The first buffer.
  auto next_result = enc_stream->Next(&buffer);
  int buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.value());
  EXPECT_EQ(buffer_size, enc_stream->Position());

  // BackUp several times, but in total fewer bytes than returned by Next().
  std::vector<int> backup_sizes = {0, 1, 5, 0, 10, 78, -42, 60, 120, -120};
  int total_backup_size = 0;
  for (auto backup_size : backup_sizes) {
    enc_stream->BackUp(backup_size);
    total_backup_size += std::max(0, backup_size);
    EXPECT_EQ(buffer_size - total_backup_size, enc_stream->Position());
  }
  EXPECT_LT(total_backup_size, next_result.value());

  // Call Next(), it should succeed (backuped bytes of 1st segment).
  next_result = enc_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(total_backup_size, next_result.value());
  EXPECT_EQ(buffer_size, enc_stream->Position());

  // BackUp() some bytes, again fewer than returned by Next().
  backup_sizes = {0, 72, -94, 37, 82};
  total_backup_size = 0;
  for (auto backup_size : backup_sizes) {
    enc_stream->BackUp(backup_size);
    total_backup_size += std::max(0, backup_size);
    EXPECT_EQ(buffer_size - total_backup_size, enc_stream->Position());
  }
  EXPECT_LT(total_backup_size, next_result.value());

  // Call Next(), it should succeed  (backuped bytes of 1st segment).
  next_result = enc_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(total_backup_size, next_result.value());
  EXPECT_EQ(buffer_size, enc_stream->Position());

  // Call Next() again, it should return a full segment (2nd segment).
  auto prev_position = enc_stream->Position();
  buffer_size = pt_segment_size;
  next_result = enc_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.value());
  EXPECT_EQ(prev_position + buffer_size, enc_stream->Position());

  // BackUp a few times, with total over the returned buffer_size.
  backup_sizes = {0, 72, -100, buffer_size / 2, 200, -25, buffer_size / 2, 42};
  total_backup_size = 0;
  for (auto backup_size : backup_sizes) {
    SCOPED_TRACE(absl::StrCat("backup_size = ", backup_size,
                              ", total_backup_size = ", total_backup_size));
    enc_stream->BackUp(backup_size);
    total_backup_size = std::min(buffer_size,
                                 total_backup_size + std::max(0, backup_size));
    EXPECT_EQ(prev_position + buffer_size - total_backup_size,
              enc_stream->Position());
  }
  EXPECT_EQ(total_backup_size, buffer_size);
  EXPECT_EQ(prev_position, enc_stream->Position());

  // Call Next() again, it should return a full segment (2nd segment);
  next_result = enc_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.value());
  EXPECT_EQ(prev_position + buffer_size, enc_stream->Position());
  EXPECT_EQ(2 * pt_segment_size - header_size, enc_stream->Position());

  // Backup the entire segment, and close the stream.
  enc_stream->BackUp(buffer_size);
  EXPECT_EQ(pt_segment_size - header_size, enc_stream->Position());
  auto close_status = enc_stream->Close();
  EXPECT_TRUE(close_status.ok()) << close_status;
  EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
            refs.ct_buf->str().size());
  // Ciphertext contains 1st segment (with header), and no traces
  // of the "empty" (backed-up) segment.
  EXPECT_EQ((pt_segment_size + DummyStreamSegmentEncrypter::kSegmentTagSize),
            refs.ct_buf->str().size());

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(absl::StatusCode::kFailedPrecondition, close_status.code());
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
