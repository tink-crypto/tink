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

#include "tink/subtle/ed25519_sign_boringssl.h"

#include <cstring>

#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "openssl/curve25519.h"
#include "tink/public_key_sign.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<std::unique_ptr<PublicKeySign>> Ed25519SignBoringSsl::New(
    absl::string_view private_key) {
  if (private_key.length() != ED25519_PRIVATE_KEY_LEN) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        absl::StrFormat("Invalid ED25519 private key size (%d). "
                        "The only valid size is %d.",
                        private_key.length(), ED25519_PRIVATE_KEY_LEN));
  }
  std::unique_ptr<PublicKeySign> sign(new Ed25519SignBoringSsl(private_key));
  return std::move(sign);
}

Ed25519SignBoringSsl::Ed25519SignBoringSsl(absl::string_view private_key)
    : private_key_(private_key) {}

util::StatusOr<std::string> Ed25519SignBoringSsl::Sign(
    absl::string_view data) const {
  data = SubtleUtilBoringSSL::EnsureNonNull(data);

  uint8_t out_sig[ED25519_SIGNATURE_LEN];
  std::memset(reinterpret_cast<void *>(&out_sig), 0, ED25519_SIGNATURE_LEN);

  if (ED25519_sign(
          out_sig, reinterpret_cast<const uint8_t *>(data.data()), data.size(),
          reinterpret_cast<const uint8_t *>(private_key_.data())) != 1) {
    return util::Status(util::error::INTERNAL, "Signing failed.");
  }

  return std::string(reinterpret_cast<char *>(out_sig), ED25519_SIGNATURE_LEN);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
