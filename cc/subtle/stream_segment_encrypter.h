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

#ifndef TINK_SUBTLE_STREAM_SEGMENT_ENCRYPTER_H_
#define TINK_SUBTLE_STREAM_SEGMENT_ENCRYPTER_H_

#include <cstdint>
#include <vector>

#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace subtle {

// StreamSegmentEncrypter is a helper class that encrypts individual
// segments of a stream.
//
// Instances of this are passed to an ...EncryptingStream. Each instance
// of a segment encrypter is used to encrypt one stream.
//
// Typically, construction of a new StreamSegmentEncrypter results
// in a generation of a new symmetric key, which is used to
// the segments of the stream.  The key itself wrapped with or derived
// from the key from StreamingAead instance. The wrapped key or the salt
// used to derive the symmetric key is part of the header.
//
// StreamSegmentEncrypter has a state: it keeps the number of segments
// encrypted so far. This state is used to encrypt each segment with different
// parameters, so that segments in the ciphertext cannot be switched.
//
// Values returned by StreamSegmentEncrypter's methods effectively define
// the layout of the resulting ciphertext stream:
//
//   | other | header | 1st ciphertext segment |
//   | ......    2nd ciphertext segment  ..... |
//   | ......    3rd ciphertext segment  ..... |
//   | ......    ...                     ..... |
//   | ......    last ciphertext segment |
//
// where the following holds:
//  * each line above, except for the last one,
//    contains get_ciphertext_segment_size() bytes
//  * each segment, except for the 1st and the last one,
//    encrypts get_plaintext_segment_size() bytes of plaintext
//  * if the ciphertext stream encrypts at least one byte of plaintext,
//    then the last segment encrypts at least one byte of plaintext
//  * 'other' is get_ciphertext_offset() bytes long, and represents potential
//    other bytes already written to the stream;  the purpose of ciphertext
//    offset is to allow alignment of ciphertext segments with segments
//    of the underlying storage or transmission stream.
class StreamSegmentEncrypter {
 public:
  // Encrypts 'plaintext' as a segment, and writes the resulting ciphertext
  // to 'ciphertext_buffer', adjusting its size as needed.
  // 'plaintext' and 'ciphertext_buffer' must refer to distinct and
  // non-overlapping space.
  // Encryption uses the current value returned by get_segment_number()
  // as the segment number, and subsequently increments the current
  // segment number.
  virtual util::Status EncryptSegment(
      const std::vector<uint8_t>& plaintext,
      bool is_last_segment,
      std::vector<uint8_t>* ciphertext_buffer) = 0;

  // Returns the header of the ciphertext stream.
  virtual const std::vector<uint8_t>& get_header() const = 0;

  // Returns the segment number that will be used for encryption
  // of the next segment.
  virtual int64_t get_segment_number() const = 0;

  // Returns the size (in bytes) of a plaintext segment.
  virtual int get_plaintext_segment_size() const = 0;

  // Returns the size (in bytes) of a ciphertext segment.
  virtual int get_ciphertext_segment_size() const = 0;

  // Returns the offset (in bytes) of the ciphertext within an encrypted stream.
  // The offset is non-negative, and not larger than
  //   ciphertext_segment_size - (header_size + segment_overhead)
  // where
  //   ciphertext_segment_size = get_ciphertext_segment_size()
  //   header_size = get_header().size()
  //   segment_overhead = ciphertext_segment_size - get_plaintext_segment_size()
  virtual int get_ciphertext_offset() const = 0;

  virtual ~StreamSegmentEncrypter() = default;

 protected:
  // Increments the segment number.
  virtual void IncSegmentNumber() = 0;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_STREAM_SEGMENT_ENCRYPTER_H_
