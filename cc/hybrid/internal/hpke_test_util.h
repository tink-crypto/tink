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

#ifndef TINK_HYBRID_INTERNAL_HPKE_TEST_UTIL_H_
#define TINK_HYBRID_INTERNAL_HPKE_TEST_UTIL_H_

#include <string>

#include "absl/strings/escaping.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {

struct HpkeTestParams {
  std::string recipient_public_key;   // pkRm
  std::string seed_for_testing;       // skEm
  std::string application_info;       // info
  std::string plaintext;              // pt
  std::string associated_data;        // aad
  std::string ciphertext;             // ct
  std::string recipient_private_key;  // skRm
  std::string encapsulated_key;       // enc

  explicit HpkeTestParams(const absl::string_view* test_vector)
      : recipient_public_key(absl::HexStringToBytes(test_vector[0])),
        seed_for_testing(absl::HexStringToBytes(test_vector[1])),
        application_info(absl::HexStringToBytes(test_vector[2])),
        plaintext(absl::HexStringToBytes(test_vector[3])),
        associated_data(absl::HexStringToBytes(test_vector[4])),
        ciphertext(absl::HexStringToBytes(test_vector[5])),
        recipient_private_key(absl::HexStringToBytes(test_vector[6])),
        encapsulated_key(absl::HexStringToBytes(test_vector[7])) {}
};

// Returns an HpkeTestParams struct for the following HPKE parameters:
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
HpkeTestParams DefaultHpkeTestParams();

// Creates an HpkeTestParams struct for the specified HpkeParams protobuf.
util::StatusOr<HpkeTestParams> CreateHpkeTestParams(
    const google::crypto::tink::HpkeParams& params);

// Creates an HpkeTestParams struct for the specified HpkeParams struct.
util::StatusOr<HpkeTestParams> CreateHpkeTestParams(
    const HpkeParams& params);

// Creates an HpkeParams protobuf from `kem`, `kdf`, and `aead`.
google::crypto::tink::HpkeParams CreateHpkeParams(
    const google::crypto::tink::HpkeKem& kem,
    const google::crypto::tink::HpkeKdf& kdf,
    const google::crypto::tink::HpkeAead& aead);

// Creates an HpkePublicKey proto from the specified HpkeParams protobuf and
// the `raw_key_bytes`.
google::crypto::tink::HpkePublicKey CreateHpkePublicKey(
    const google::crypto::tink::HpkeParams& params,
    const std::string& raw_key_bytes);

// Creates an HpkePrivateKey proto from the specified HpkeParams protobuf and
// the `raw_key_bytes`.  Note that the key material for the embedded
// HpkePublicKey `public_key` field will be empty.
google::crypto::tink::HpkePrivateKey CreateHpkePrivateKey(
    const google::crypto::tink::HpkeParams& params,
    const std::string& raw_key_bytes);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_TEST_UTIL_H_
