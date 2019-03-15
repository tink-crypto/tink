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

#ifndef TINK_SUBTLE_AES_GCM_HKDF_STREAMING_H_
#define TINK_SUBTLE_AES_GCM_HKDF_STREAMING_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "tink/input_stream.h"
#include "tink/output_stream.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/nonce_based_streaming_aead.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class AesGcmHkdfStreaming : public NonceBasedStreamingAead {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<AesGcmHkdfStreaming>>
  New(absl::string_view ikm,
      HashType hkdf_hash,
      int derived_key_size,
      int ciphertext_segment_size,
      int first_segment_offset);

  ~AesGcmHkdfStreaming() override {}

 protected:
  crypto::tink::util::StatusOr<std::unique_ptr<StreamSegmentEncrypter>>
  NewSegmentEncrypter(absl::string_view associated_data) const override;

  crypto::tink::util::StatusOr<std::unique_ptr<StreamSegmentDecrypter>>
  NewSegmentDecrypter(absl::string_view associated_data) const override;

 private:
  AesGcmHkdfStreaming() {}
  std::string ikm_;
  HashType hkdf_hash_;
  int derived_key_size_;
  int ciphertext_segment_size_;
  int first_segment_offset_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_GCM_HKDF_STREAMING_H_
