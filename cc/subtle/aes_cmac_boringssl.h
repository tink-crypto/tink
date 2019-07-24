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

#include "absl/strings/string_view.h"
#include "tink/mac.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class AesCmacBoringSsl : public Mac {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<Mac>> New(
      const std::string& key_value, uint32_t tag_size);

  // Computes and returns the CMAC for 'data'.
  crypto::tink::util::StatusOr<std::string> ComputeMac(
      absl::string_view data) const override;

  // Verifies if 'mac' is a correct CMAC for 'data'.
  // Returns Status::OK if 'mac' is correct, and a non-OK-Status otherwise.
  crypto::tink::util::Status VerifyMac(absl::string_view mac,
                                       absl::string_view data) const override;

  ~AesCmacBoringSsl() override {}

 private:
  // CMAC key sizes in bytes.
  // The small key size is used only to check RFC 4493's test vectors due to
  // the attack described in
  // https://www.math.uwaterloo.ca/~ajmeneze/publications/tightness.pdf. We
  // check this restriction in AesCmacManager.
  static const size_t kSmallKeySize = 16;
  static const size_t kBigKeySize = 32;
  static const size_t kMaxTagSize = 16;

  AesCmacBoringSsl(const std::string& key_value, uint32_t tag_size);

  const std::string key_value_;
  const uint32_t tag_size_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_CMAC_BORINGSSL_H_
