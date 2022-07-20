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

#ifndef TINK_SUBTLE_AES_CTR_HMAC_STREAMING_H_
#define TINK_SUBTLE_AES_CTR_HMAC_STREAMING_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "tink/internal/fips_utils.h"
#include "tink/mac.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/nonce_based_streaming_aead.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// Streaming encryption using AES-CTR and HMAC.
//
// Each ciphertext uses a new AES-CTR key and HMAC key that are derived from the
// key derivation key, a randomly chosen salt of the same size as the key and a
// nonce prefix using HKDF.
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
class AesCtrHmacStreaming : public NonceBasedStreamingAead {
 public:
  struct Params {
    util::SecretData ikm;
    HashType hkdf_algo;
    int key_size;
    int ciphertext_segment_size;
    int ciphertext_offset;
    HashType tag_algo;
    int tag_size;
  };

  // The size of the nonce for AES-CTR.
  static constexpr int kNonceSizeInBytes = 16;

  // The nonce has the format nonce_prefix || ctr || last_block || 0 0 0 0,
  // where:
  //  - nonce_prefix is a constant of kNoncePrefixSizeInBytes bytes
  //    for the whole file
  //  - ctr is a big endian 32 bit counter
  //  - last_block is a byte equal to 1 for the last block of the file
  //    and 0 otherwise.
  static constexpr int kNoncePrefixSizeInBytes = 7;

  static constexpr int kHmacKeySizeInBytes = 32;

  static util::StatusOr<std::unique_ptr<AesCtrHmacStreaming>> New(
      Params params);

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

 protected:
  util::StatusOr<std::unique_ptr<StreamSegmentEncrypter>> NewSegmentEncrypter(
      absl::string_view associated_data) const override;

  util::StatusOr<std::unique_ptr<StreamSegmentDecrypter>> NewSegmentDecrypter(
      absl::string_view associated_data) const override;

 private:
  explicit AesCtrHmacStreaming(Params params) : params_(std::move(params)) {}
  const Params params_;
};

class AesCtrHmacStreamSegmentEncrypter : public StreamSegmentEncrypter {
 public:
  // A factory.
  static util::StatusOr<std::unique_ptr<StreamSegmentEncrypter>> New(
      const AesCtrHmacStreaming::Params& params,
      absl::string_view associated_data);

  // Overridden methods of StreamSegmentEncrypter.
  util::Status EncryptSegment(const std::vector<uint8_t>& plaintext,
                              bool is_last_segment,
                              std::vector<uint8_t>* ciphertext_buffer) override;

  const std::vector<uint8_t>& get_header() const override { return header_; }
  int64_t get_segment_number() const override { return segment_number_; }
  int get_plaintext_segment_size() const override {
    return ciphertext_segment_size_ - tag_size_;
  }
  int get_ciphertext_segment_size() const override {
    return ciphertext_segment_size_;
  }
  int get_ciphertext_offset() const override { return ciphertext_offset_; }

 protected:
  void IncSegmentNumber() override { segment_number_++; }

 private:
  AesCtrHmacStreamSegmentEncrypter(util::SecretData key_value,
                                   absl::string_view header,
                                   absl::string_view nonce_prefix,
                                   int ciphertext_segment_size,
                                   int ciphertext_offset, int tag_size,
                                   const EVP_CIPHER* cipher,
                                   std::unique_ptr<Mac> mac)
      : key_value_(std::move(key_value)),
        header_(header.begin(), header.end()),
        nonce_prefix_(nonce_prefix),
        ciphertext_segment_size_(ciphertext_segment_size),
        ciphertext_offset_(ciphertext_offset),
        tag_size_(tag_size),
        cipher_(cipher),
        mac_(std::move(mac)),
        segment_number_(0) {}

  const util::SecretData key_value_;
  const std::vector<uint8_t> header_;
  const std::string nonce_prefix_;
  const int ciphertext_segment_size_;
  const int ciphertext_offset_;
  const int tag_size_;
  const EVP_CIPHER* cipher_;
  const std::unique_ptr<Mac> mac_;
  int64_t segment_number_;
};

class AesCtrHmacStreamSegmentDecrypter : public StreamSegmentDecrypter {
 public:
  // A factory.
  static util::StatusOr<std::unique_ptr<StreamSegmentDecrypter>> New(
      const AesCtrHmacStreaming::Params& params,
      absl::string_view associated_data);

  // Overridden methods of StreamSegmentDecrypter.
  util::Status Init(const std::vector<uint8_t>& header) override;

  util::Status DecryptSegment(const std::vector<uint8_t>& ciphertext,
                              int64_t segment_number, bool is_last_segment,
                              std::vector<uint8_t>* plaintext_buffer) override;

  int get_header_size() const override {
    return 1 + key_size_ + AesCtrHmacStreaming::kNoncePrefixSizeInBytes;
  }
  int get_plaintext_segment_size() const override {
    return ciphertext_segment_size_ - tag_size_;
  }
  int get_ciphertext_segment_size() const override {
    return ciphertext_segment_size_;
  }
  int get_ciphertext_offset() const override { return ciphertext_offset_; }
  ~AesCtrHmacStreamSegmentDecrypter() override {}

 private:
  AesCtrHmacStreamSegmentDecrypter(util::SecretData ikm, HashType hkdf_algo,
                                   int key_size,
                                   absl::string_view associated_data,
                                   int ciphertext_segment_size,
                                   int ciphertext_offset, HashType tag_algo,
                                   int tag_size)
      : ikm_(std::move(ikm)),
        hkdf_algo_(hkdf_algo),
        key_size_(key_size),
        associated_data_(associated_data),
        ciphertext_segment_size_(ciphertext_segment_size),
        ciphertext_offset_(ciphertext_offset),
        tag_algo_(tag_algo),
        tag_size_(tag_size) {}

  // Parameters set upon decrypter creation.
  const util::SecretData ikm_;
  const HashType hkdf_algo_;
  const int key_size_;
  const std::string associated_data_;
  const int ciphertext_segment_size_;
  const int ciphertext_offset_;
  const HashType tag_algo_;
  const int tag_size_;

  // Parameters set when initializing with data from stream header.
  bool is_initialized_ = false;
  util::SecretData key_value_;
  std::string nonce_prefix_;
  const EVP_CIPHER* cipher_;
  std::unique_ptr<Mac> mac_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_CTR_HMAC_STREAMING_H_
