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

#ifndef TINK_HYBRID_INTERNAL_HPKE_ENCRYPT_H_
#define TINK_HYBRID_INTERNAL_HPKE_ENCRYPT_H_

#include <memory>
#include <string>

#include "tink/hybrid/internal/hpke_encrypt_boringssl.h"
#include "tink/hybrid_encrypt.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {

class HpkeEncrypt : public HybridEncrypt {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<HybridEncrypt>> New(
      const google::crypto::tink::HpkePublicKey& recipient_public_key);

  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view context_info) const override;

 private:
  explicit HpkeEncrypt(
      const google::crypto::tink::HpkePublicKey& recipient_public_key)
      : recipient_public_key_(recipient_public_key) {}

  google::crypto::tink::HpkePublicKey recipient_public_key_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_ENCRYPT_H_
