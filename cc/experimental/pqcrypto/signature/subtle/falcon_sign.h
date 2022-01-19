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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SUBTLE_FALCON_SIGN_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SUBTLE_FALCON_SIGN_H_

#include <memory>
#include <string>
#include <utility>

#include "tink/experimental/pqcrypto/signature/subtle/falcon_subtle_utils.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// Post-Quantum Signing using Falcon - Fast-Fourier Lattice-based
// Compact Signature over NTRU
class FalconSign : public PublicKeySign {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static crypto::tink::util::StatusOr<std::unique_ptr<PublicKeySign>> New(
      const FalconPrivateKeyPqclean& private_key);

  ~FalconSign() override = default;

  // Computes the signature for 'data'.
  crypto::tink::util::StatusOr<std::string> Sign(
      absl::string_view data) const override;

 private:
  explicit FalconSign(const FalconPrivateKeyPqclean& private_key)
      : private_key_(private_key) {}

  const FalconPrivateKeyPqclean private_key_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SUBTLE_FALCON_SIGN_H_
