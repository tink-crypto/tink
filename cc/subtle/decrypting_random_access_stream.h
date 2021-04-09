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

#ifndef TINK_SUBTLE_DECRYPTING_RANDOM_ACCESS_STREAM_H_
#define TINK_SUBTLE_DECRYPTING_RANDOM_ACCESS_STREAM_H_

#include <memory>
#include <vector>

#include "absl/synchronization/mutex.h"
#include "tink/random_access_stream.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// A RandomAccessStream that wraps another RandomAccessStream
// as a ciphertext source, and provides a "plaintext access" to
// the plaintext data contained in the ciphertext:
//  - PRead()-calls to this class read appropriate segments
//    of the ciphertext, decrypt them, and return the resulting
//    plaintext, where the 'position' and 'count' arguments
//    refer to the plaintext bytes.
//  - size()-call returns the size of the entire plaintext
//    if it were to be decrypted.
// Instances of this class are thread safe.
class DecryptingRandomAccessStream : public crypto::tink::RandomAccessStream {
 public:
  // A factory that produces decrypting random access streams.
  // The returned stream is a wrapper around 'ciphertext_source',
  // such that any bytes written via the wrapper are AEAD-decrypted
  // by 'segment_decrypter' using 'associated_data' as associated
  // authenticated data.
  static crypto::tink::util::StatusOr<
      std::unique_ptr<crypto::tink::RandomAccessStream>>
  New(std::unique_ptr<StreamSegmentDecrypter> segment_decrypter,
      std::unique_ptr<crypto::tink::RandomAccessStream> ciphertext_source);

  // -----------------------
  // Methods of RandomAccessStream-interface implemented by this class.
  crypto::tink::util::Status PRead(
      int64_t position, int count,
      crypto::tink::util::Buffer* dest_buffer) override;
  crypto::tink::util::StatusOr<int64_t> size() override;

 private:
  DecryptingRandomAccessStream() {}
  crypto::tink::util::Status PReadAndDecrypt(
      int64_t position, int count, crypto::tink::util::Buffer* dest_buffer);
  // Reads the specified ciphertext segment from ct_source_, decrypts it,
  // and writes the resulting plaintext bytes to pt_segment.
  // Uses the provided ct_buffer as a buffer for the ciphertext segment.
  crypto::tink::util::Status ReadAndDecryptSegment(
      int64_t segment_nr, crypto::tink::util::Buffer* ct_buffer,
      std::vector<uint8_t>* pt_segment);
  // Returns the segment number that contains the specified 'pt_position'.
  int64_t GetSegmentNr(int64_t pt_position);
  // Returns the offset within a segment for the specified 'pt_position'.
  int GetPlaintextOffset(int64_t pt_position);
  // Initializes this stream (if not initialized yet or in a permantent error)
  // by reading the stream header from ct_source_ and using it initialize
  // segment_decrypter_.
  void InitializeIfNeeded();
  std::unique_ptr<StreamSegmentDecrypter> segment_decrypter_;
  std::unique_ptr<crypto::tink::RandomAccessStream> ct_source_;

  mutable absl::Mutex status_mutex_;
  crypto::tink::util::Status status_ ABSL_GUARDED_BY(status_mutex_);
  int header_size_;
  int ct_offset_;
  int ct_segment_size_;
  int pt_segment_size_;
  int ct_segment_overhead_;
  int64_t segment_count_;
  int64_t pt_size_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_DECRYPTING_RANDOM_ACCESS_STREAM_H_
