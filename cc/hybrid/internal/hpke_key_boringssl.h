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

#ifndef TINK_HYBRID_INTERNAL_HPKE_KEY_BORINGSSL_H_
#define TINK_HYBRID_INTERNAL_HPKE_KEY_BORINGSSL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "openssl/hpke.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {

class ABSL_DEPRECATED("Store keys in util::SecretData.") HpkeKeyBoringSsl {
 public:
  // Initializes an HPKE recipient private key.  Returns an error if
  // initialization fails.  Otherwise, returns a unique pointer to the key.
  //
  //   `kem`: HPKE KEM parameter.
  //   `recipient_private_key`: KEM-encoding of recipient private key.
  static util::StatusOr<std::unique_ptr<HpkeKeyBoringSsl>> New(
      const google::crypto::tink::HpkeKem& kem,
      absl::string_view recipient_private_key);

  // HpkeKeyBoringSsl objects are neither movable, nor copyable.
  HpkeKeyBoringSsl(HpkeKeyBoringSsl&& other) = delete;
  HpkeKeyBoringSsl& operator=(HpkeKeyBoringSsl&& other) = delete;
  HpkeKeyBoringSsl(const HpkeKeyBoringSsl&) = delete;
  HpkeKeyBoringSsl& operator=(const HpkeKeyBoringSsl&) = delete;

  const google::crypto::tink::HpkeKem& kem() const { return kem_; }

  const EVP_HPKE_KEY* recipient_private_key() const {
    return recipient_private_key_.get();
  }

 private:
  explicit HpkeKeyBoringSsl(const google::crypto::tink::HpkeKem& kem)
      : kem_(kem) {}

  util::Status Init(absl::string_view recipient_private_key);

  google::crypto::tink::HpkeKem kem_;
  bssl::ScopedEVP_HPKE_KEY recipient_private_key_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_KEY_BORINGSSL_H_
