// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_SUBTLE_PRF_HKDF_STREAMING_PRF_H_
#define TINK_SUBTLE_PRF_HKDF_STREAMING_PRF_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/prf/streaming_prf.h"
#include "tink/internal/fips_utils.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class HkdfStreamingPrf : public StreamingPrf {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<StreamingPrf>> New(
      HashType hash, util::SecretData secret, absl::string_view salt);

  std::unique_ptr<InputStream> ComputePrf(
      absl::string_view input) const override;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

 private:
  HkdfStreamingPrf(const EVP_MD* hash, util::SecretData secret,
                   absl::string_view salt)
      : hash_(hash), secret_(std::move(secret)), salt_(salt) {}

  const EVP_MD* hash_;
  const util::SecretData secret_;
  const std::string salt_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_PRF_HKDF_STREAMING_PRF_H_
