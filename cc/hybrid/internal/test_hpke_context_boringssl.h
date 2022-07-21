// Copyright 2022 Google LLC
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

#ifndef TINK_HYBRID_INTERNAL_TEST_HPKE_CONTEXT_BORINGSSL_H_
#define TINK_HYBRID_INTERNAL_TEST_HPKE_CONTEXT_BORINGSSL_H_

#include <stddef.h>

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/hpke.h"
#include "tink/hybrid/internal/hpke_context_boringssl.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

class TestHpkeContextBoringSsl : public HpkeContextBoringSsl {
 public:
  // Sets up a test HPKE sender context.  Returns an error if initialization
  // fails.  Otherwise, returns a unique pointer to the sender context.
  //
  //   `params`: HPKE parameters (KEM, KDF, and AEAD).
  //   `recipient_public_key`: KEM-encoding of recipient public key.
  //   `info`: Application-specific context for key derivation.
  //   `seed_for_testing`: Seed used to match test vector values.
  static crypto::tink::util::StatusOr<SenderHpkeContextBoringSsl> SetupSender(
      const HpkeParams& params, absl::string_view recipient_public_key,
      absl::string_view info, absl::string_view seed_for_testing);

 private:
  explicit TestHpkeContextBoringSsl(SslUniquePtr<EVP_HPKE_CTX> context)
      : HpkeContextBoringSsl(std::move(context)) {}
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_TEST_HPKE_CONTEXT_BORINGSSL_H_
