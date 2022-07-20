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

#ifndef TINK_SUBTLE_HKDF_H_
#define TINK_SUBTLE_HKDF_H_

#include <string>

#include "absl/strings/string_view.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// TODO(wiktorg) delete non-SecretData variant once all clients are migrated
class Hkdf {
 public:
  // Computes hkdf according to RFC5869.
  static crypto::tink::util::StatusOr<std::string> ComputeHkdf(
      HashType hash, absl::string_view ikm, absl::string_view salt,
      absl::string_view info, size_t out_len);
  static crypto::tink::util::StatusOr<util::SecretData> ComputeHkdf(
      HashType hash, const util::SecretData& ikm, absl::string_view salt,
      absl::string_view info, size_t out_len);

  // Computes symmetric key for ECIES with HKDF from the provided parameters.
  // This function follows Shoup's recommendation of including ECIES
  // ephemeral KEM bytes into the commputation of the symmetric key
  // (cf. http://eprint.iacr.org/2001/112.pdf, Sections 15.6 and 15.6.1)
  static crypto::tink::util::StatusOr<util::SecretData>
  ComputeEciesHkdfSymmetricKey(HashType hash, absl::string_view kem_bytes,
                               const util::SecretData& shared_secret,
                               absl::string_view salt, absl::string_view info,
                               size_t out_len);
};
}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_HKDF_H_
