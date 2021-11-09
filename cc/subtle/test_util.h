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

#ifndef TINK_SUBTLE_TEST_UTIL_H_
#define TINK_SUBTLE_TEST_UTIL_H_

#include <string>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/input_stream.h"
#include "tink/output_stream.h"
#include "tink/subtle/nonce_based_streaming_aead.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace test {

// Various utilities for testing.
///////////////////////////////////////////////////////////////////////////////

// Writes 'contents' the specified 'output_stream', and if 'close_stream'
// is true, then closes the stream.
// Returns the status of output_stream->Close()-operation, or a non-OK status
// of a prior output_stream->Next()-operation, if any.
util::Status WriteToStream(OutputStream* output_stream,
                           absl::string_view contents,
                           bool close_stream = true);

// Reads all bytes from the specified 'input_stream', and puts
// them into 'output', where both 'input_stream' and 'output must be non-null.
// Returns a non-OK status only if reading fails for some reason.
// If the end of stream is reached ('input_stream' returns OUT_OF_RANGE),
// then this function returns OK.
util::Status ReadFromStream(InputStream* input_stream, std::string* output);

// A dummy encrypter that "encrypts" by just appending to the plaintext
// the current segment number and a marker byte indicating whether
// the segment is last one.
class DummyStreamSegmentEncrypter : public StreamSegmentEncrypter {
 public:
  // Size of the per-segment tag added upon encryption.
  static constexpr int kSegmentTagSize = sizeof(int64_t) + 1;

  // Bytes for marking whether a given segment is the last one.
  static constexpr char kLastSegment = 'l';
  static constexpr char kNotLastSegment = 'n';

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

  // Generates an expected ciphertext for the given 'plaintext'.
  std::string GenerateCiphertext(absl::string_view plaintext) {
    std::string ct(header_.begin(), header_.end());
    int64_t seg_no = 0;
    int pos = 0;
    do {
      int seg_len = pt_segment_size_;
      if (pos == 0) {  // The first segment.
        seg_len -= (ct_offset_ + header_.size());
      }
      if (seg_len > plaintext.size() - pos) {  // The last segment.
        seg_len = plaintext.size() - pos;
      }
      ct.append(plaintext.substr(pos, seg_len).data(), seg_len);
      pos += seg_len;
      ct.append(reinterpret_cast<const char*>(&seg_no), sizeof(seg_no));
      ct.append(1, pos < plaintext.size() ? kNotLastSegment : kLastSegment);
      seg_no++;
    } while (pos < plaintext.size());
    return ct;
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
    return util::OkStatus();
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

// A dummy decrypter that "decrypts" segments encrypted by
// DummyStreamSegmentEncrypter.
class DummyStreamSegmentDecrypter : public StreamSegmentDecrypter {
 public:
  DummyStreamSegmentDecrypter(int pt_segment_size,
                              int header_size,
                              int ct_offset) :
      pt_segment_size_(pt_segment_size),
      ct_offset_(ct_offset) {
    // Fill the header with 'header_size' copies of letter 'h'
    header_.resize(0);
    header_.resize(header_size, static_cast<uint8_t>('h'));
    generated_output_size_ = 0;
  }

  util::Status Init(const std::vector<uint8_t>& header) override {
    if (header_.size() != header.size() ||
        memcmp(header_.data(), header.data(), header_.size()) != 0) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid stream header");
    }
    return util::OkStatus();
  }

  int get_header_size() const override {
    return header_.size();
  }

  util::Status DecryptSegment(
      const std::vector<uint8_t>& ciphertext,
      int64_t segment_number,
      bool is_last_segment,
      std::vector<uint8_t>* plaintext_buffer) override {
    if (ciphertext.size() < DummyStreamSegmentEncrypter::kSegmentTagSize) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Ciphertext segment too short");
    }
    if (ciphertext.back() !=
        (is_last_segment ? DummyStreamSegmentEncrypter::kLastSegment :
         DummyStreamSegmentEncrypter::kNotLastSegment)) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "unexpected last-segment marker");
    }
    int pt_size =
        ciphertext.size() - DummyStreamSegmentEncrypter::kSegmentTagSize;
    if (memcmp(ciphertext.data() + pt_size,
               reinterpret_cast<const char*>(&segment_number),
               sizeof(segment_number)) != 0) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "wrong segment number");
    }
    plaintext_buffer->resize(pt_size);
    memcpy(plaintext_buffer->data(), ciphertext.data(), pt_size);
    generated_output_size_ += pt_size;
    return util::OkStatus();
  }


  int get_plaintext_segment_size() const override {
    return pt_segment_size_;
  }

  int get_ciphertext_segment_size() const override {
    return pt_segment_size_ + DummyStreamSegmentEncrypter::kSegmentTagSize;
  }

  int get_ciphertext_offset() const override {
    return ct_offset_;
  }

  ~DummyStreamSegmentDecrypter() override {}

  int get_generated_output_size() {
    return generated_output_size_;
  }

 private:
  std::vector<uint8_t> header_;
  int pt_segment_size_;
  int ct_offset_;
  int64_t generated_output_size_;
};   // class DummyStreamSegmentDecrypter

class DummyStreamingAead : public NonceBasedStreamingAead {
 public:
  DummyStreamingAead(int pt_segment_size, int header_size, int ct_offset)
      : pt_segment_size_(pt_segment_size),
        header_size_(header_size),
        ct_offset_(ct_offset) {}

 protected:
  util::StatusOr<std::unique_ptr<StreamSegmentEncrypter>> NewSegmentEncrypter(
      absl::string_view associated_data) const override {
    return {absl::make_unique<DummyStreamSegmentEncrypter>(
        pt_segment_size_, header_size_, ct_offset_)};
  }

  util::StatusOr<std::unique_ptr<StreamSegmentDecrypter>> NewSegmentDecrypter(
      absl::string_view associated_data) const override {
    return {absl::make_unique<DummyStreamSegmentDecrypter>(
        pt_segment_size_, header_size_, ct_offset_)};
  }

 private:
  int pt_segment_size_;
  int header_size_;
  int ct_offset_;
};

}  // namespace test
}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_TEST_UTIL_H_
