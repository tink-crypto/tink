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

#include <sstream>
#include <vector>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/output_stream.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/subtle/random.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

using crypto::tink::OutputStream;
using crypto::tink::util::OstreamOutputStream;
using crypto::tink::util::Status;

namespace crypto {
namespace tink {
namespace subtle {
namespace {

// Writes 'contents' the specified 'output_stream', and closes the stream.
// Returns the status of output_stream->Close()-operation, or a non-OK status
// of a prior output_stream->Next()-operation, if any.
Status WriteToStream(OutputStream* output_stream,
                     absl::string_view contents) {
  void* buffer;
  int pos = 0;
  int remaining = contents.length();
  int available_space;
  int available_bytes;
  while (remaining > 0) {
    auto next_result = output_stream->Next(&buffer);
    if (!next_result.ok()) return next_result.status();
    available_space = next_result.ValueOrDie();
    available_bytes = std::min(available_space, remaining);
    memcpy(buffer, contents.data() + pos, available_bytes);
    remaining -= available_bytes;
    pos += available_bytes;
  }
  if (available_space > available_bytes) {
    output_stream->BackUp(available_space - available_bytes);
  }
  return output_stream->Close();
}

// Size of the per-segment tag added upon encryption.
const int kSegmentTagSize = sizeof(int64_t) + 1;

// Bytes for marking whether a given segment is the last one.
const char kLastSegment = 'l';
const char kNotLastSegment = 'n';


// A dummy encrypter that "encrypts" by just appending to the plaintext
// the current segment number and a marker byte indicating whether
// the segment is last one.
class DummyStreamSegmentEncrypter : public StreamSegmentEncrypter {
 public:
  DummyStreamSegmentEncrypter(int pt_segment_size,
                              int header_size,
                              int ct_offset) :
      pt_segment_size_(pt_segment_size),
      ct_offset_(ct_offset),
      segment_number_(0) {
    // Fill the header with 'header_size' copies of letter 'h'
    header_.resize(0);
    header_.resize(header_size, static_cast<uint8_t>('h'));
    generated_output_size_ = header_size;
  }

  util::Status EncryptSegment(
      const std::vector<uint8_t>& plaintext,
      bool is_last_segment,
      std::vector<uint8_t>* ciphertext_buffer) override {
    ciphertext_buffer->resize(plaintext.size() + kSegmentTagSize);
    memcpy(ciphertext_buffer->data(), plaintext.data(), plaintext.size());
    memcpy(ciphertext_buffer->data() + plaintext.size(),
           &segment_number_, sizeof(segment_number_));
    // The last byte of the a ciphertext segment.
    ciphertext_buffer->back() =
        is_last_segment ? kLastSegment : kNotLastSegment;
    generated_output_size_ += ciphertext_buffer->size();
    IncSegmentNumber();
    return Status::OK;
  }

  const std::vector<uint8_t>& get_header() const override {
    return header_;
  }

  int64_t get_segment_number() const override {
    return segment_number_;
  }

  int get_plaintext_segment_size() const override {
    return pt_segment_size_;
  }

  int get_ciphertext_segment_size() const override {
    return pt_segment_size_ + kSegmentTagSize;
  }

  int get_ciphertext_offset() const override {
    return ct_offset_;
  }

  ~DummyStreamSegmentEncrypter() override {}

  int get_generated_output_size() {
    return generated_output_size_;
  }

 protected:
  void IncSegmentNumber() override {
    segment_number_++;
  }

 private:
  std::vector<uint8_t> header_;
  int pt_segment_size_;
  int ct_offset_;
  int64_t segment_number_;
  int64_t generated_output_size_;
};   // class DummyStreamSegmentEncrypter

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
      std::move(seg_enc), std::move(ct_destination)).ValueOrDie());
  EXPECT_EQ(0, enc_stream->Position());
  return enc_stream;
}


class StreamingAeadEncryptingStreamTest : public ::testing::Test {
};

TEST_F(StreamingAeadEncryptingStreamTest, WritingStreams) {
  std::vector<int> pt_sizes = {0, 10, 100, 1000, 10000, 100000, 1000000};
  std::vector<int> pt_segment_sizes = {64, 100, 128, 1000, 1024};
  std::vector<int> header_sizes = {5, 10, 32};
  std::vector<int> ct_offset_deltas = {0, 1, 5, 15};
  for (auto pt_size : pt_sizes) {
    for (auto pt_segment_size : pt_segment_sizes) {
      for (auto header_size : header_sizes) {
        for (auto offset_delta : ct_offset_deltas) {
          SCOPED_TRACE(absl::StrCat("pt_size = ", pt_size,
                                    ", pt_segment_size = ", pt_segment_size,
                                    ", header_size = ", header_size,
                                    ", offset_delta = ", offset_delta));
          // Get an encrypting stream.
          ValidationRefs refs;
          auto enc_stream = GetEncryptingStream(pt_segment_size, header_size,
              /* ct_offset = */ header_size + offset_delta, &refs);

          // First buffer returned by Next();
          void* buffer;
          auto next_result = enc_stream->Next(&buffer);
          EXPECT_TRUE(next_result.ok()) << next_result.status();
          int buffer_size = next_result.ValueOrDie();
          EXPECT_EQ(pt_segment_size - header_size - offset_delta, buffer_size);
          EXPECT_EQ(buffer_size, enc_stream->Position());

          // Backup the entire first buffer.
          enc_stream->BackUp(buffer_size);
          EXPECT_EQ(0, enc_stream->Position());

          // Write plaintext to the stream, and close the stream.
          std::string pt = Random::GetRandomBytes(pt_size);
          auto status = WriteToStream(enc_stream.get(), pt);
          EXPECT_TRUE(status.ok()) << status;
          EXPECT_EQ(enc_stream->Position(), pt.size());
          EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
                    refs.ct_buf->str().size());
          EXPECT_EQ(std::string(header_size, 'h'),
                    refs.ct_buf->str().substr(0, header_size));

          // Try closing the stream again.
          status = enc_stream->Close();
          EXPECT_FALSE(status.ok());
          EXPECT_EQ(util::error::FAILED_PRECONDITION, status.error_code());
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
      pt_segment_size, header_size, /* ct_offset = */ header_size, &refs);

  // Close the stream.
  auto close_status = enc_stream->Close();
  EXPECT_TRUE(close_status.ok()) << close_status;
  EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
            refs.ct_buf->str().size());
  // Ciphertext contains only the header and an "empty" first block.
  EXPECT_EQ(header_size + kSegmentTagSize, refs.ct_buf->str().size());
  // The last segment is marked as such.
  EXPECT_EQ(kLastSegment, refs.ct_buf->str().back());

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(util::error::FAILED_PRECONDITION, close_status.error_code());
}

TEST_F(StreamingAeadEncryptingStreamTest, EmptyPlaintextWithBackup) {
  int pt_segment_size = 512;
  int header_size = 64;
  void* buffer;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ header_size, &refs);

  // Get the first block.
  auto next_result = enc_stream->Next(&buffer);
  int buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, enc_stream->Position());

  // Backup the entire block, and close the stream.
  enc_stream->BackUp(buffer_size);
  EXPECT_EQ(0, enc_stream->Position());
  auto close_status = enc_stream->Close();
  EXPECT_TRUE(close_status.ok()) << close_status;
  EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
            refs.ct_buf->str().size());
  // Ciphertext contains only the header and an "empty" first block.
  EXPECT_EQ(header_size + kSegmentTagSize, refs.ct_buf->str().size());
  // The last segment is marked as such.
  EXPECT_EQ(kLastSegment, refs.ct_buf->str().back());

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(util::error::FAILED_PRECONDITION, close_status.error_code());
}

TEST_F(StreamingAeadEncryptingStreamTest, OneSegmentPlaintext) {
  int pt_segment_size = 512;
  int header_size = 64;
  void* buffer;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ header_size, &refs);

  // Get the first segment, and close the stream.
  auto next_result = enc_stream->Next(&buffer);
  int buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, enc_stream->Position());
  auto close_status = enc_stream->Close();
  EXPECT_TRUE(close_status.ok()) << close_status;
  EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
            refs.ct_buf->str().size());
  // Ciphertext contains only header and a full first block.
  EXPECT_EQ(pt_segment_size + kSegmentTagSize, refs.ct_buf->str().size());
  // The last segment is marked as such.
  EXPECT_EQ(kLastSegment, refs.ct_buf->str().back());

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(util::error::FAILED_PRECONDITION, close_status.error_code());
}

TEST_F(StreamingAeadEncryptingStreamTest, OneSegmentPlaintextWithBackup) {
  int pt_segment_size = 512;
  int pt_size = 200;
  int header_size = 64;
  void* buffer;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ header_size, &refs);

  // Get the first block.
  auto next_result = enc_stream->Next(&buffer);
  int buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, enc_stream->Position());

  // Backup so that only pt_size bytes are written, and close the stream.
  enc_stream->BackUp(buffer_size - pt_size);
  EXPECT_EQ(pt_size, enc_stream->Position());
  auto close_status = enc_stream->Close();
  EXPECT_TRUE(close_status.ok()) << close_status;
  EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
            refs.ct_buf->str().size());
  // Ciphertext contains only the header and partial first block.
  EXPECT_EQ(header_size + pt_size + kSegmentTagSize, refs.ct_buf->str().size());
  // The last segment is marked as such.
  EXPECT_EQ(kLastSegment, refs.ct_buf->str().back());

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(util::error::FAILED_PRECONDITION, close_status.error_code());
}

TEST_F(StreamingAeadEncryptingStreamTest, ManySegmentsPlaintext) {
  int pt_segment_size = 512;
  int header_size = 64;
  void* buffer;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ header_size, &refs);

  int seg_count = 5;
  // Get the first segment.
  auto next_result = enc_stream->Next(&buffer);
  int first_buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(first_buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(first_buffer_size, enc_stream->Position());

  // Get remaining segments.
  for (int i = 1; i < seg_count; i++) {
    next_result = enc_stream->Next(&buffer);
    EXPECT_TRUE(next_result.ok()) << next_result.status();
    EXPECT_EQ(pt_segment_size, next_result.ValueOrDie());
    EXPECT_EQ(first_buffer_size + i * pt_segment_size, enc_stream->Position());
  }

  // Close the stream.
  auto close_status = enc_stream->Close();
  EXPECT_TRUE(close_status.ok()) << close_status;
  EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
            refs.ct_buf->str().size());
  // Ciphertext contains seg_count full segments.
  int ct_segment_size = pt_segment_size + kSegmentTagSize;
  EXPECT_EQ(refs.seg_enc->get_ciphertext_segment_size(), ct_segment_size);
  EXPECT_EQ(ct_segment_size * seg_count, refs.ct_buf->str().size());
  // The last segment is marked as such.
  EXPECT_EQ(kLastSegment, refs.ct_buf->str().back());
  // The previous segments are marked as not-last ones.
  for (int i = 1; i < seg_count - 1; i++) {
    EXPECT_EQ(kNotLastSegment, refs.ct_buf->str()[(ct_segment_size * i)-1]);
  }

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(util::error::FAILED_PRECONDITION, close_status.error_code());
}

TEST_F(StreamingAeadEncryptingStreamTest, ManySegmentsPlaintextWithBackup) {
  int pt_segment_size = 512;
  int backup_size = 100;
  int header_size = 64;
  void* buffer;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ header_size, &refs);

  int seg_count = 5;
  // Get the first segment.
  auto next_result = enc_stream->Next(&buffer);
  int first_buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(first_buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(first_buffer_size, enc_stream->Position());

  // Get remaining segments.
  for (int i = 1; i < seg_count; i++) {
    next_result = enc_stream->Next(&buffer);
    EXPECT_TRUE(next_result.ok()) << next_result.status();
    EXPECT_EQ(pt_segment_size, next_result.ValueOrDie());
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
  int ct_segment_size = pt_segment_size + kSegmentTagSize;
  EXPECT_EQ(refs.seg_enc->get_ciphertext_segment_size(), ct_segment_size);
  EXPECT_EQ(ct_segment_size * seg_count - backup_size,
            refs.ct_buf->str().size());
  // The last segment is marked as such.
  EXPECT_EQ(kLastSegment, refs.ct_buf->str().back());
  // The previous segments are marked as not-last ones.
  for (int i = 1; i < seg_count - 1; i++) {
    EXPECT_EQ(kNotLastSegment, refs.ct_buf->str()[(ct_segment_size * i)-1]);
  }

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(util::error::FAILED_PRECONDITION, close_status.error_code());
}

TEST_F(StreamingAeadEncryptingStreamTest, ManySegmentsPlaintextWithFullBackup) {
  int pt_segment_size = 512;
  int header_size = 64;
  void* buffer;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ header_size, &refs);

  int seg_count = 5;
  // Get the first segment.
  auto next_result = enc_stream->Next(&buffer);
  int first_buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(first_buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(first_buffer_size, enc_stream->Position());

  // Get remaining segments.
  for (int i = 1; i < seg_count; i++) {
    next_result = enc_stream->Next(&buffer);
    EXPECT_TRUE(next_result.ok()) << next_result.status();
    EXPECT_EQ(pt_segment_size, next_result.ValueOrDie());
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
  int ct_segment_size = pt_segment_size + kSegmentTagSize;
  EXPECT_EQ(refs.seg_enc->get_ciphertext_segment_size(), ct_segment_size);
  EXPECT_EQ(ct_segment_size * (seg_count - 1), refs.ct_buf->str().size());
  // The last segment is marked as such.
  EXPECT_EQ(kLastSegment, refs.ct_buf->str().back());
  // The previous segments are marked as not-last ones.
  for (int i = 1; i < seg_count - 1; i++) {
    EXPECT_EQ(kNotLastSegment, refs.ct_buf->str()[(ct_segment_size * i)-1]);
  }

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(util::error::FAILED_PRECONDITION, close_status.error_code());
}

TEST_F(StreamingAeadEncryptingStreamTest, BackupAndPosition) {
  int pt_segment_size = 512;
  int header_size = 64;
  void* buffer;

  // Get an encrypting stream.
  ValidationRefs refs;
  auto enc_stream = GetEncryptingStream(
      pt_segment_size, header_size, /* ct_offset = */ header_size, &refs);

  // The first buffer.
  auto next_result = enc_stream->Next(&buffer);
  int buffer_size = pt_segment_size - header_size;
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, enc_stream->Position());

  // BackUp several times, but in total fewer bytes than returned by Next().
  std::vector<int> backup_sizes = {0, 1, 5, 0, 10, 78, -42, 60, 120, -120};
  int total_backup_size = 0;
  for (auto backup_size : backup_sizes) {
    enc_stream->BackUp(backup_size);
    total_backup_size += std::max(0, backup_size);
    EXPECT_EQ(buffer_size - total_backup_size, enc_stream->Position());
  }
  EXPECT_LT(total_backup_size, next_result.ValueOrDie());

  // Call Next(), it should succeed (backuped bytes of 1st block).
  next_result = enc_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(total_backup_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, enc_stream->Position());

  // BackUp() some bytes, again fewer than returned by Next().
  backup_sizes = {0, 72, -94, 37, 82};
  total_backup_size = 0;
  for (auto backup_size : backup_sizes) {
    enc_stream->BackUp(backup_size);
    total_backup_size += std::max(0, backup_size);
    EXPECT_EQ(buffer_size - total_backup_size, enc_stream->Position());
  }
  EXPECT_LT(total_backup_size, next_result.ValueOrDie());

  // Call Next(), it should succeed  (backuped bytes of 1st block).
  next_result = enc_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(total_backup_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, enc_stream->Position());

  // Call Next() again, it should return a full block (2nd block).
  auto prev_position = enc_stream->Position();
  buffer_size = pt_segment_size;
  next_result = enc_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
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

  // Call Next() again, it should return a full block (2nd block);
  next_result = enc_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(prev_position + buffer_size, enc_stream->Position());
  EXPECT_EQ(2 * pt_segment_size - header_size, enc_stream->Position());

  // Backup the entire block, and close the stream.
  enc_stream->BackUp(buffer_size);
  EXPECT_EQ(pt_segment_size - header_size, enc_stream->Position());
  auto close_status = enc_stream->Close();
  EXPECT_TRUE(close_status.ok()) << close_status;
  EXPECT_EQ(refs.seg_enc->get_generated_output_size(),
            refs.ct_buf->str().size());
  // Ciphertext contains 1st segment (with header), and no traces
  // of the "empty" (backed-up) block.
  EXPECT_EQ((pt_segment_size + kSegmentTagSize), refs.ct_buf->str().size());

  // Try closing the stream again.
  close_status = enc_stream->Close();
  EXPECT_FALSE(close_status.ok());
  EXPECT_EQ(util::error::FAILED_PRECONDITION, close_status.error_code());
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
