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
#ifndef TINK_SUBTLE_HRSS_BORINGSSL_H_
#define TINK_SUBTLE_HRSS_BORINGSSL_H_

#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/hrss.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// BoringSSL implementation of the NTRU-HRSS scheme.
//
// The NTRU-HRSS is a structured lattice-based key encapsulation mechanism. It
// was originally proposed in [1] and submitted to the NIST Post-Quantum
// Cryptography standardization process [2].
//
// During the course of the NIST PQC standardization process, the NTRU-HRSS
// proposal merged with another proposal (NTRUEncrypt). The resulting scheme,
// simply called NTRU [3], is a 3rd round finalist of the NIST PQC
// standardization process.
//
// The implementation available in BoringSSL is based on [1] but it
// uses a different KEM construction based on [4]. Note that the BoringSSL
// implementation is *not* compatible with the 3rd Round finalist NTRU running
// in the NIST Post-Quantum Cryptography standardization process.
//
// References:
// [1]: https://eprint.iacr.org/2017/667.pdf
// [2]: https://csrc.nist.gov/Projects/post-quantum-cryptography/
// [3]: https://ntru.org/
// [4]: https://eprint.iacr.org/2017/1005.pdf
class HrssKem {
 public:
  struct KemCiphertextSharedKey {
    std::string kem_ciphertext;
    util::SecretData kem_shared_key = util::SecretData(HRSS_KEY_BYTES, 0);
  };
  static crypto::tink::util::StatusOr<std::unique_ptr<HrssKem>> New();
  crypto::tink::util::StatusOr<KemCiphertextSharedKey> Encapsulate(
      const absl::string_view in_plaintext);
  crypto::tink::util::StatusOr<util::SecretData> Decapsulate(
      const absl::string_view in_ciphertext);

 private:
  HrssKem() = default;
  struct HRSS_public_key pub_;
  util::SecretUniquePtr<struct HRSS_private_key> priv_ =
      util::MakeSecretUniquePtr<struct HRSS_private_key>();
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_HRSS_BORINGSSL_H_
