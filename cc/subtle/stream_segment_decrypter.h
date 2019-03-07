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

#ifndef TINK_SUBTLE_STREAM_SEGMENT_DECRYPTER_H_
#define TINK_SUBTLE_STREAM_SEGMENT_DECRYPTER_H_

#include <vector>

#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace subtle {

// StreamSegmentDecrypter is a helper class that decrypts individual
// segments of a stream.
//
// Instances of this are passed to an ...DecryptingStream. Each instance
// of a segment decrypter must be initialized with a header of a ciphertext
// stream and is used to decrypt that stream.
//
// See stream_segment_encrypter.h for more info on the structure of
// a ciphertext stream.
class StreamSegmentDecrypter {
 public:
  // Decrypts 'ciphertext' as a segment, and writes the resulting plaintext
  // to 'plaintext_buffer', adjusting its size as needed.
  // 'ciphertext' and 'plaintext_buffer' must refer to distinct and
  // non-overlapping space.
  // Decryption uses the current value returned by get_segment_number()
  // as the segment number, and subsequently increments the current
  // segment number.
  virtual util::Status DecryptSegment(
      const std::vector<uint8_t>& ciphertext,
      int64_t segment_number,
      bool is_last_segment,
      std::vector<uint8_t>* plaintext_buffer) = 0;

  // Initializes this decrypter, using the information from 'header',
  // which must be of size exactly get_header_size().
  virtual util::Status Init(const std::vector<uint8_t>& header) = 0;

  // Returns the size (in bytes) of the header of a ciphertext stream.
  virtual int get_header_size() const = 0;

  // Returns the size (in bytes) of a plaintext segment.
  virtual int get_plaintext_segment_size() const = 0;

  // Returns the size (in bytes) of a ciphertext segment.
  virtual int get_ciphertext_segment_size() const = 0;

  // Returns the offset (in bytes) of the ciphertext within an decrypted stream.
  // The offset is not smaller than the size of the header.
  virtual int get_ciphertext_offset() const = 0;

  virtual ~StreamSegmentDecrypter() {}
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_STREAM_SEGMENT_DECRYPTER_H_
