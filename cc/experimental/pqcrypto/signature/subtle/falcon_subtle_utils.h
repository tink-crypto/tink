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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SUBTLE_FALCON_SUBTLE_UTILS_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SUBTLE_FALCON_SUBTLE_UTILS_H_

#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// The two possible falcon private key sizes, as defined at
// https://falcon-sign.info/.

const int kFalcon512PrivateKeySize = 1281;
const int kFalcon1024PrivateKeySize = 2305;

// The two possible falcon public key sizes as defined at
// https://falcon-sign.info/.
const int kFalcon512PublicKeySize = 897;
const int kFalcon1024PublicKeySize = 1793;

// Representation of the Falcon private key.
class FalconPrivateKeyPqclean {
 public:
  // Creates a new FalconPrivateKeyPqclean from key_data.
  static util::StatusOr<FalconPrivateKeyPqclean> NewPrivateKey(
      const util::SecretData& key_data);

  FalconPrivateKeyPqclean(const FalconPrivateKeyPqclean& other) = default;
  FalconPrivateKeyPqclean& operator=(const FalconPrivateKeyPqclean& other) =
      default;

  const util::SecretData& GetKey() const { return key_data_; }

 private:
  explicit FalconPrivateKeyPqclean(const util::SecretData& key_data)
      : key_data_(key_data) {}

  const util::SecretData key_data_;
};

// Representation of the Falcon public key.
class FalconPublicKeyPqclean {
 public:
  // Creates a new FalconPublicKeyPqclean from key_data.
  static util::StatusOr<FalconPublicKeyPqclean> NewPublicKey(
      absl::string_view key_data);

  FalconPublicKeyPqclean(const FalconPublicKeyPqclean& other) = default;
  FalconPublicKeyPqclean& operator=(const FalconPublicKeyPqclean& other) =
      default;

  const std::string& GetKey() const { return key_data_; }

 private:
  explicit FalconPublicKeyPqclean(absl::string_view key_data)
      : key_data_(std::move(key_data)) {}

  const std::string key_data_;
};

class FalconKeyPair {
 public:
  FalconKeyPair(FalconPrivateKeyPqclean private_key,
                FalconPublicKeyPqclean public_key)
      : private_key_(std::move(private_key)),
        public_key_(std::move(public_key)) {}

  FalconKeyPair(const FalconKeyPair& other) = default;
  FalconKeyPair& operator=(const FalconKeyPair& other) = default;

  const FalconPrivateKeyPqclean& GetPrivateKey() const { return private_key_; }
  const FalconPublicKeyPqclean& GetPublicKey() const { return public_key_; }

 private:
  const FalconPrivateKeyPqclean private_key_;
  const FalconPublicKeyPqclean public_key_;
};

// This is an utility function that generates a new Falcon key pair.
// This function is expected to be called from a key manager class.
crypto::tink::util::StatusOr<FalconKeyPair> GenerateFalconKeyPair(
    int32 private_key_size);

// Validates whether the private key size is safe to use for falcon signature.
crypto::tink::util::Status ValidateFalconPrivateKeySize(int32_t key_size);

// Validates whether the public key size is safe to use for falcon signature.
crypto::tink::util::Status ValidateFalconPublicKeySize(int32_t key_size);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SUBTLE_FALCON_SUBTLE_UTILS_H_
