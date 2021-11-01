// Copyright 2017 Google Inc.
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

#include "tink/subtle/hkdf.h"

#include "absl/algorithm/container.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "openssl/evp.h"
#include "openssl/hkdf.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<util::SecretData> Hkdf::ComputeHkdf(HashType hash,
                                                   const util::SecretData &ikm,
                                                   absl::string_view salt,
                                                   absl::string_view info,
                                                   size_t out_len) {
  auto status_or_evp_md = SubtleUtilBoringSSL::EvpHash(hash);
  if (!status_or_evp_md.ok()) {
    return status_or_evp_md.status();
  }
  util::SecretData out_key(out_len);
  if (1 != HKDF(out_key.data(), out_len, status_or_evp_md.ValueOrDie(),
                ikm.data(), ikm.size(),
                reinterpret_cast<const uint8_t *>(salt.data()), salt.size(),
                reinterpret_cast<const uint8_t *>(info.data()), info.size())) {
    return util::Status(absl::StatusCode::kInternal, "BoringSSL's HKDF failed");
  }
  return out_key;
}

util::StatusOr<std::string> Hkdf::ComputeHkdf(HashType hash,
                                              absl::string_view ikm,
                                              absl::string_view salt,
                                              absl::string_view info,
                                              size_t out_len) {
  auto status_or_evp_md = SubtleUtilBoringSSL::EvpHash(hash);
  if (!status_or_evp_md.ok()) {
    return status_or_evp_md.status();
  }
  std::string out_key(out_len, '\0');
  if (1 != HKDF(reinterpret_cast<uint8_t *>(&out_key[0]), out_len,
                status_or_evp_md.ValueOrDie(),
                reinterpret_cast<const uint8_t *>(ikm.data()), ikm.size(),
                reinterpret_cast<const uint8_t *>(salt.data()), salt.size(),
                reinterpret_cast<const uint8_t *>(info.data()), info.size())) {
    return util::Status(absl::StatusCode::kInternal, "BoringSSL's HKDF failed");
  }
  return out_key;
}

util::StatusOr<util::SecretData> Hkdf::ComputeEciesHkdfSymmetricKey(
    HashType hash, absl::string_view kem_bytes,
    const util::SecretData &shared_secret, absl::string_view salt,
    absl::string_view info, size_t out_len) {
  util::SecretData ikm(kem_bytes.size() + shared_secret.size());
  absl::c_copy(kem_bytes, ikm.begin());
  absl::c_copy(shared_secret, ikm.begin() + kem_bytes.size());
  return Hkdf::ComputeHkdf(hash, ikm, salt, info, out_len);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
