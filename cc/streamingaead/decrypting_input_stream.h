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

#ifndef TINK_STREAMINGAEAD_DECRYPTING_INPUT_STREAM_H_
#define TINK_STREAMINGAEAD_DECRYPTING_INPUT_STREAM_H_

#include <memory>
#include <string>
#include <vector>

#include "tink/input_stream.h"
#include "tink/primitive_set.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/buffered_input_stream.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace streamingaead {

// A wrapper around an InputStream that holds a reference to a
// set of StreamingAead-primitives and upon first Next()-call probes the
// initial portion of the wrapped InputStream, to find a matching
// primitive, i.e. the primitive that is able to decrypt the stream.
// Once a match is found, all subsequent calls are forwarded to it.
class DecryptingInputStream : public crypto::tink::InputStream {
 public:
  // Constructs an InputStream that wraps 'input_stream', and will use
  // (one of) provided 'primitives' to decrypt the contents of 'input_stream',
  // using 'associated_data' as authenticated associated data
  // of the decryption process.
  static util::StatusOr<std::unique_ptr<InputStream>> New(
      std::shared_ptr<
          crypto::tink::PrimitiveSet<crypto::tink::StreamingAead>> primitives,
      std::unique_ptr<crypto::tink::InputStream> ciphertext_source,
      absl::string_view associated_data);

  ~DecryptingInputStream() override {}
  util::StatusOr<int> Next(const void** data) override;
  void BackUp(int count) override;
  int64_t Position() const override;

 private:
  DecryptingInputStream() {}
  std::shared_ptr<
      crypto::tink::PrimitiveSet<crypto::tink::StreamingAead>> primitives_;
  std::shared_ptr<BufferedInputStream> buffered_ct_source_;
  std::string associated_data_;
  std::unique_ptr<crypto::tink::InputStream> matching_stream_;
  bool attempted_matching_;
};

}  // namespace streamingaead
}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMINGAEAD_DECRYPTING_INPUT_STREAM_H_
