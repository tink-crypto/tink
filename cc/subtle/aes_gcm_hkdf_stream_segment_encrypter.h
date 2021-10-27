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

#ifndef TINK_SUBTLE_AES_GCM_HKDF_STREAM_SEGMENT_ENCRYPTER_H_
#define TINK_SUBTLE_AES_GCM_HKDF_STREAM_SEGMENT_ENCRYPTER_H_

#include <memory>
#include <string>
#include <vector>

#include "openssl/aead.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// StreamSegmentEncrypter for streaming encryption using AES-GCM with HKDF as
// key derivation function.
//
// Each ciphertext uses a new AES-GCM key that is derived from the key
// derivation key, a randomly chosen salt of the same size as the key and a
// nonce prefix.
//
// The format of a ciphertext is
//   header || segment_0 || segment_1 || ... || segment_k.
// where:
//  - segment_i is the i-th segment of the ciphertext.
//  - the size of segment_1 .. segment_{k-1} is get_ciphertext_segment_size()
//  - segment_0 is shorter, so that segment_0, the header and other information
//    of size get_ciphertext_offset() align with get_ciphertext_segment_size().
//
// The format of the header is
//   header_size || salt || nonce_prefix
// where
//  - header_size is 1 byte determining the size of the header
//  - salt is a salt used in the key derivation
//  - nonce_prefix is the prefix of the nonce
//
// In principle header_size is redundant information, since the length of the
// header can be determined from the key size.

class AesGcmHkdfStreamSegmentEncrypter : public StreamSegmentEncrypter {
 public:
  // The size of the IVs for GCM.
  static constexpr int kNonceSizeInBytes = 12;

  // The nonce has the format nonce_prefix || ctr || last_block, where:
  //  - nonce_prefix is a constant of kNoncePrefixSizeInBytes bytes
  //    for the whole file
  //  - ctr is a 32 bit counter
  //  - last_block is a byte equal to 1 for the last block of the file
  //    and 0 otherwise.
  static constexpr int kNoncePrefixSizeInBytes = 7;

  // The size of the tags of each ciphertext segment.
  static constexpr int kTagSizeInBytes = 16;

  struct Params {
    util::SecretData key;
    std::string salt;
    int ciphertext_offset;
    int ciphertext_segment_size;
  };

  // A factory.
  static util::StatusOr<std::unique_ptr<StreamSegmentEncrypter>> New(
      Params params);

  // Overridden methods of StreamSegmentEncrypter.
  util::Status EncryptSegment(const std::vector<uint8_t>& plaintext,
                              bool is_last_segment,
                              std::vector<uint8_t>* ciphertext_buffer) override;

  const std::vector<uint8_t>& get_header() const override { return header_; }
  int64_t get_segment_number() const override { return segment_number_; }
  int get_plaintext_segment_size() const override;
  int get_ciphertext_segment_size() const override {
    return ciphertext_segment_size_;
  }
  int get_ciphertext_offset() const override { return ciphertext_offset_; }

 protected:
  void IncSegmentNumber() override { segment_number_++; }

 private:
  AesGcmHkdfStreamSegmentEncrypter(internal::SslUniquePtr<EVP_AEAD_CTX> ctx,
                                   const Params& params);

  internal::SslUniquePtr<EVP_AEAD_CTX> ctx_;
  const std::string nonce_prefix_;
  const std::vector<uint8_t> header_;
  const int ciphertext_segment_size_;
  const int ciphertext_offset_;

  int64_t segment_number_ = 0;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_GCM_HKDF_STREAM_SEGMENT_ENCRYPTER_H_
