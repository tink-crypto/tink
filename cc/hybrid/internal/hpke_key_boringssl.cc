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

#include "tink/hybrid/internal/hpke_key_boringssl.h"

#include <utility>

#include "openssl/base.h"
#include "openssl/err.h"
#include "openssl/hpke.h"
#include "tink/hybrid/internal/hpke_util_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using ::google::crypto::tink::HpkeKem;

util::StatusOr<std::unique_ptr<HpkeKeyBoringSsl>> HpkeKeyBoringSsl::New(
    const HpkeKem& kem, absl::string_view recipient_private_key) {
  std::unique_ptr<HpkeKeyBoringSsl> hpke_key =
      absl::WrapUnique(new HpkeKeyBoringSsl(kem));
  util::Status status = hpke_key->Init(recipient_private_key);
  if (!status.ok()) {
    return status;
  }
  return hpke_key;
}

util::Status HpkeKeyBoringSsl::Init(absl::string_view recipient_private_key) {
  util::StatusOr<const EVP_HPKE_KEM*> hpke_kem = KemParam(kem_);
  if (!hpke_kem.ok()) {
    return hpke_kem.status();
  }
  if (!EVP_HPKE_KEY_init(
          recipient_private_key_.get(), *hpke_kem,
          reinterpret_cast<const uint8_t*>(recipient_private_key.data()),
          recipient_private_key.size())) {
    return util::Status(
        util::error::UNKNOWN,
        "Unable to initialize BoringSSL HPKE recipient private key.");
  }
  return util::OkStatus();
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
