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

#include "pqcrypto/cc/subtle/cecpq2_subtle_boringssl_util.h"

#include "openssl/hrss.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace pqc {

crypto::tink::util::StatusOr<crypto::tink::pqc::HrssKeyPair> GetNewHrssKey(
    util::SecretData hrss_key_entropy) {
  crypto::tink::pqc::HrssKeyPair hrss_key_pair;

  // struct HRSS_public_key pk_dumb;
  HRSS_generate_key(&hrss_key_pair.hrss_public_key,
                    hrss_key_pair.hrss_private_key.get(),
                    hrss_key_entropy.data());

  crypto::tink::subtle::ResizeStringUninitialized(
      &(hrss_key_pair.hrss_public_key_marshaled), HRSS_PUBLIC_KEY_BYTES);

  HRSS_marshal_public_key(
      const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(
          hrss_key_pair.hrss_public_key_marshaled.data())),
      &(hrss_key_pair.hrss_public_key));

  return hrss_key_pair;
}

}  // namespace pqc
}  // namespace tink
}  // namespace crypto
