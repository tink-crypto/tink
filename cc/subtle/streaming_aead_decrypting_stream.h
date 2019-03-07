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

#ifndef TINK_SUBTLE_STREAMING_AEAD_DECRYPTING_STREAM_H_
#define TINK_SUBTLE_STREAMING_AEAD_DECRYPTING_STREAM_H_

#include <memory>
#include <vector>

#include "tink/input_stream.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class StreamingAeadDecryptingStream : public InputStream {
 public:
  // A factory that produces decrypting streams.
  // The returned stream is a wrapper around 'ciphertext_destination',
  // such that any bytes written via the wrapper are AEAD-decrypted
  // by 'segment_decrypter' using 'associated_data' as associated
  // authenticated data.
  static
  crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::InputStream>>
      New(std::unique_ptr<StreamSegmentDecrypter> segment_decrypter,
          std::unique_ptr<crypto::tink::InputStream> ciphertext_source);

  // -----------------------
  // Methods of InputStream-interface implemented by this class.
  crypto::tink::util::StatusOr<int> Next(const void** data) override;
  void BackUp(int count) override;
  int64_t Position() const override;

 private:
  StreamingAeadDecryptingStream() {}
  std::unique_ptr<StreamSegmentDecrypter> segment_decrypter_;
  std::unique_ptr<crypto::tink::InputStream> ct_source_;
  std::vector<uint8_t> ct_buffer_;  // ciphertext buffer
  std::vector<uint8_t> pt_buffer_;  // plaintext buffer
  int64_t position_;  // number of plaintext bytes read from this stream
  int64_t segment_number_;  // current segment number
  crypto::tink::util::Status status_;  // status of the stream

  // Counters that describe the state of the data in pt_buffer_.
  int count_backedup_;    // # bytes in pt_buffer_ that were backed up
  int pt_buffer_offset_;  // offset at which *data starts in pt_buffer_

  // Flag that indicates whether the decrypting stream has been initialized.
  // If true, the header of the ciphertext stream has been already read
  // and processed.
  bool is_initialized_;
  bool read_last_segment_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_STREAMING_AEAD_DECRYPTING_STREAM_H_
