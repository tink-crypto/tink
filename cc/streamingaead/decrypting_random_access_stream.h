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

#ifndef TINK_STREAMINGAEAD_DECRYPTING_RANDOM_ACCESS_STREAM_H_
#define TINK_STREAMINGAEAD_DECRYPTING_RANDOM_ACCESS_STREAM_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/synchronization/mutex.h"
#include "tink/primitive_set.h"
#include "tink/random_access_stream.h"
#include "tink/streaming_aead.h"
#include "tink/util/buffer.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace streamingaead {

// A wrapper around a RandomAccessStream that holds a reference to a
// set of StreamingAead-primitives and upon first PRead()-call attempts
// to read the stream via the provided primitives to find a matching one,
// i.e. the primitive that is able to decrypt the stream.
// Once a match is found, all subsequent calls are forwarded to it.
class DecryptingRandomAccessStream : public crypto::tink::RandomAccessStream {
 public:
  // Constructs an RandomAccessStream that wraps 'random_access_stream',
  // and will use (one of) provided 'primitives' to decrypt the contents
  // of 'random_access_stream', using 'associated_data' as authenticated
  // associated data of the decryption process.
  static util::StatusOr<std::unique_ptr<RandomAccessStream>> New(
      std::shared_ptr<
          crypto::tink::PrimitiveSet<crypto::tink::StreamingAead>> primitives,
      std::unique_ptr<crypto::tink::RandomAccessStream> ciphertext_source,
      absl::string_view associated_data);

  ~DecryptingRandomAccessStream() override {}
  crypto::tink::util::Status PRead(int64_t position, int count,
      crypto::tink::util::Buffer* dest_buffer) override;
  crypto::tink::util::StatusOr<int64_t> size() override;

 private:
  DecryptingRandomAccessStream(
      std::shared_ptr<
          crypto::tink::PrimitiveSet<crypto::tink::StreamingAead>> primitives,
      std::unique_ptr<crypto::tink::RandomAccessStream> ciphertext_source,
      absl::string_view associated_data)
      : primitives_(primitives),
        ciphertext_source_(std::move(ciphertext_source)),
        associated_data_(associated_data),
        attempted_matching_(false),
        matching_stream_(nullptr) {}
  std::shared_ptr<
      crypto::tink::PrimitiveSet<crypto::tink::StreamingAead>> primitives_;
  std::unique_ptr<crypto::tink::RandomAccessStream> ciphertext_source_;
  std::string associated_data_;
  mutable absl::Mutex matching_mutex_;
  bool attempted_matching_ ABSL_GUARDED_BY(matching_mutex_);
  std::unique_ptr<crypto::tink::RandomAccessStream> matching_stream_
      ABSL_GUARDED_BY(matching_mutex_);
};

}  // namespace streamingaead
}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMINGAEAD_DECRYPTING_RANDOM_ACCESS_STREAM_H_
