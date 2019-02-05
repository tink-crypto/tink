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

#ifndef TINK_SUBTLE_ED25519_SIGN_BORINGSSL_H_
#define TINK_SUBTLE_ED25519_SIGN_BORINGSSL_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "openssl/curve25519.h"
#include "tink/public_key_sign.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class Ed25519SignBoringSsl : public PublicKeySign {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<PublicKeySign>> New(
      absl::string_view private_key);

  // Computes the signature for 'data'.
  crypto::tink::util::StatusOr<std::string> Sign(
      absl::string_view data) const override;

  ~Ed25519SignBoringSsl() override = default;

 private:
  const std::string private_key_;

  explicit Ed25519SignBoringSsl(absl::string_view private_key);
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_ED25519_SIGN_BORINGSSL_H_
