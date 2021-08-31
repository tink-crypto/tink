// Copyright 2021 Google LLC
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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SUBTLE_SPHINCS_SUBTLE_UTILS_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SUBTLE_SPHINCS_SUBTLE_UTILS_H_

#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/str_format.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

enum SphincsHashType {
  HARAKA = 0,
  SHA256 = 1,
  SHAKE256 = 2,
};

enum SphincsVariant {
  ROBUST = 0,
  SIMPLE = 1,
};

enum SphincsSignatureLengthType {
  F = 0,
  S = 1,
};

class SphincsPrivateKeyPqclean {
 public:
  explicit SphincsPrivateKeyPqclean(util::SecretData key_data)
      : private_key_data_(std::move(key_data)) {}

  SphincsPrivateKeyPqclean(const SphincsPrivateKeyPqclean& other) = default;
  SphincsPrivateKeyPqclean& operator=(const SphincsPrivateKeyPqclean& other) =
      default;

  const util::SecretData& Get() const { return private_key_data_; }

 private:
  const util::SecretData private_key_data_;
};

class SphincsPublicKeyPqclean {
 public:
  explicit SphincsPublicKeyPqclean(std::string key_data)
      : public_key_data_(std::move(key_data)) {}

  SphincsPublicKeyPqclean(const SphincsPublicKeyPqclean& other) = default;
  SphincsPublicKeyPqclean& operator=(const SphincsPublicKeyPqclean& other) =
      default;

  const std::string& Get() const { return public_key_data_; }

 private:
  const std::string public_key_data_;
};

class SphincsKeyPair {
 public:
  SphincsKeyPair(SphincsPrivateKeyPqclean private_key,
                 SphincsPublicKeyPqclean public_key)
      : private_key_(private_key), public_key_(public_key) {}

  SphincsKeyPair(const SphincsKeyPair& other) = default;
  SphincsKeyPair& operator=(const SphincsKeyPair& other) =
      default;

  const SphincsPrivateKeyPqclean& GetPrivateKey() const { return private_key_; }
  const SphincsPublicKeyPqclean& GetPublicKey() const { return public_key_; }

 private:
  SphincsPrivateKeyPqclean private_key_;
  SphincsPublicKeyPqclean public_key_;
};

struct SphincsParams {
  SphincsHashType hash_type;
  SphincsVariant variant;
  SphincsSignatureLengthType sig_length_type;
  int32 private_key_size;

  SphincsParams(SphincsHashType hash_type_, SphincsVariant variant_,
                int32 private_key_size_,
                SphincsSignatureLengthType sig_length_type_) {
    hash_type = hash_type_;
    variant = variant_;
    private_key_size = private_key_size_;
    sig_length_type = sig_length_type_;
  }
};

// This is an utility function that generates a new Sphincs key pair based on
// Sphincs specific parameters. This function is expected to be called from
// a key manager class.
crypto::tink::util::StatusOr<SphincsKeyPair> GenerateSphincsKeyPair(
    SphincsParams params);

// Validates whether 'key_size' is safe to use for sphincs signature.
crypto::tink::util::Status ValidateKeySize(int32 key_size);

// Convert the sphincs private key size to the appropiate index in the
// pqclean functions array.
crypto::tink::util::StatusOr<int32> SphincsKeySizeToIndex(int32 key_size);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SUBTLE_SPHINCS_SUBTLE_UTILS_H_
