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

#ifndef TINK_SUBTLE_AES_CMAC_BORINGSSL_H_
#define TINK_SUBTLE_AES_CMAC_BORINGSSL_H_

#include <memory>
#include <string>
#include <utility>

#include "tink/internal/fips_utils.h"
#include "tink/mac.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class AesCmacBoringSsl : public Mac {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<Mac>> New(
      util::SecretData key, uint32_t tag_size);

  // Computes and returns the CMAC for 'data'.
  crypto::tink::util::StatusOr<std::string> ComputeMac(
      absl::string_view data) const override;

  // Verifies if 'mac' is a correct CMAC for 'data'.
  // Returns Status::OK if 'mac' is correct, and a non-OK-Status otherwise.
  crypto::tink::util::Status VerifyMac(absl::string_view mac,
                                       absl::string_view data) const override;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

 private:
  AesCmacBoringSsl(util::SecretData key, uint32_t tag_size)
      : key_(std::move(key)), tag_size_(tag_size) {}

  const util::SecretData key_;
  const uint32_t tag_size_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_CMAC_BORINGSSL_H_
