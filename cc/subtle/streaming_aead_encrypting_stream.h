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

#ifndef TINK_SUBTLE_STREAMING_AEAD_ENCRYPTING_STREAM_H_
#define TINK_SUBTLE_STREAMING_AEAD_ENCRYPTING_STREAM_H_

#include <memory>
#include <vector>

#include "tink/output_stream.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class NonceBasedStreamingAead;

class StreamingAeadEncryptingStream : public OutputStream {
 public:
  // A factory that produces encrypting streams.
  // The returned stream is a wrapper around 'ciphertext_destination',
  // such that any bytes written via the wrapper are streaming AEAD-encrypted
  // via 'nonce_based_streaming_aead' using 'associated_data' as
  // associated authenticated data.
  static
  crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::OutputStream>>
      New(std::unique_ptr<StreamSegmentEncrypter> segment_encrypter,
          std::unique_ptr<crypto::tink::OutputStream> ciphertext_destination);

  // -----------------------
  // Methods of OutputStream-interface implemented by this class.
  crypto::tink::util::StatusOr<int> Next(void** data) override;
  void BackUp(int count) override;
  crypto::tink::util::Status Close() override;
  int64_t Position() const override;

 private:
  StreamingAeadEncryptingStream() {}
  std::unique_ptr<StreamSegmentEncrypter> segment_encrypter_;
  std::unique_ptr<crypto::tink::OutputStream> ciphertext_destination_;
  std::vector<uint8_t> plaintext_buffer_;
  std::vector<uint8_t> ciphertext_buffer_;
  int64_t position_;  // number of plaintext bytes written to this stream
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_STREAMING_AEAD_ENCRYPTING_STREAM_H_
