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

#include <algorithm>
#include <iterator>

#include "absl/memory/memory.h"
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
    util::SecretData private_key) {
  auto status = internal::CheckFipsCompatibility<Ed25519SignBoringSsl>();
  if (!status.ok()) return status;

  if (private_key.size() != ED25519_PRIVATE_KEY_LEN) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        absl::StrFormat("Invalid ED25519 private key size (%d). "
                        "The only valid size is %d.",
                        private_key.size(), ED25519_PRIVATE_KEY_LEN));
  }
  return {absl::WrapUnique(new Ed25519SignBoringSsl(std::move(private_key)))};
}

util::StatusOr<std::string> Ed25519SignBoringSsl::Sign(
    absl::string_view data) const {
  data = SubtleUtilBoringSSL::EnsureNonNull(data);

  uint8_t out_sig[ED25519_SIGNATURE_LEN];
  std::fill(std::begin(out_sig), std::end(out_sig), 0);

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
