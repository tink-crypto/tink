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

#ifndef TINK_STREAMINGAEAD_STREAMING_AEAD_KEY_TEMPLATES_H_
#define TINK_STREAMINGAEAD_STREAMING_AEAD_KEY_TEMPLATES_H_

#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Pre-generated KeyTemplate for StreamingAead key types. One can use these
// templates to generate new KeysetHandle object with fresh keys.
// To generate a new keyset that contains a single AesGcmKey, one can do:
//
//   auto status = StreamingAeadConfig::Register();
//   if (!status.ok()) { /* fail with error */ }
//   auto handle_result = KeysetHandle::GenerateNew(
//       StreamingAeadKeyTemplates::Aes128GcmHkdf4KB());
//   if (!handle_result.ok()) { /* fail with error */ }
//   auto keyset_handle = std::move(handle_result.value());
class StreamingAeadKeyTemplates {
 public:
  // Returns a KeyTemplate that generates new instances of
  // AesGcmHkdfStreamingKey with the following parameters:
  //   - main key (ikm) size: 16 bytes
  //   - HKDF algorithm: HMAC-SHA256
  //   - size of derived AES-GCM keys: 16 bytes
  //   - ciphertext segment size: 4096 bytes
  //   - OutputPrefixType: RAW
  static const google::crypto::tink::KeyTemplate& Aes128GcmHkdf4KB();

  // Returns a KeyTemplate that generates new instances of
  // AesGcmHkdfStreamingKey with the following parameters:
  //   - main key (ikm) size: 32 bytes
  //   - HKDF algorithm: HMAC-SHA256
  //   - size of derived AES-GCM keys: 32 bytes
  //   - ciphertext segment size: 4096 bytes
  //   - OutputPrefixType: RAW
  static const google::crypto::tink::KeyTemplate& Aes256GcmHkdf4KB();

  // Returns a KeyTemplate that generates new instances of
  // AesGcmHkdfStreamingKey with the following parameters:
  //   - main key (ikm) size: 32 bytes
  //   - HKDF algorithm: HMAC-SHA256
  //   - size of derived AES-GCM keys: 32 bytes
  //   - ciphertext segment size: 1048576 bytes (1 MB)
  //   - OutputPrefixType: RAW
  static const google::crypto::tink::KeyTemplate& Aes256GcmHkdf1MB();

  // Returns a KeyTemplate that generates new instances of
  // AesCtrHmacStreamingKey with the following parameters:
  //   - main key (ikm) size: 16 bytes
  //   - HKDF algorithm: HMAC-SHA256
  //   - size of derived AES-CTR keys: 16 bytes
  //   - tag algorithm: HMAC-SHA256
  //   - tag size: 32 bytes
  //   - ciphertext segment size: 4096 bytes
  //   - OutputPrefixType: RAW
  static const google::crypto::tink::KeyTemplate&
  Aes128CtrHmacSha256Segment4KB();

  // Returns a KeyTemplate that generates new instances of
  // AesCtrHmacStreamingKey with the following parameters:
  //   - main key (ikm) size: 32 bytes
  //   - HKDF algorithm: HMAC-SHA256
  //   - size of derived AES-CTR keys: 32 bytes
  //   - tag algorithm: HMAC-SHA256
  //   - tag size: 32 bytes
  //   - ciphertext segment size: 4096 bytes
  //   - OutputPrefixType: RAW
  static const google::crypto::tink::KeyTemplate&
  Aes256CtrHmacSha256Segment4KB();
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMINGAEAD_STREAMING_AEAD_KEY_TEMPLATES_H_
