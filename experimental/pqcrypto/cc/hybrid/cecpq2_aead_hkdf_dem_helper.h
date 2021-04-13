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

#ifndef THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_HYBRID_CECPQ2_AEAD_HKDF_DEM_HELPER_H_
#define THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_HYBRID_CECPQ2_AEAD_HKDF_DEM_HELPER_H_

#include <memory>

#include "tink/aead.h"
#include "tink/daead/subtle/aead_or_daead.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// A helper for DEM (data encapsulation mechanism) of CECPQ2-AEAD-HKDF.
class Cecpq2AeadHkdfDemHelper {
 public:
  // Constructs a new helper for the specified DEM key template.
  static crypto::tink::util::StatusOr<
      std::unique_ptr<const Cecpq2AeadHkdfDemHelper>>
  New(const google::crypto::tink::KeyTemplate& dem_key_template);

  virtual ~Cecpq2AeadHkdfDemHelper() {}

  // Creates and returns a new AeadOrDaead object that uses
  // a 32-bytes or greater high-entropy seed to generate a key.
  virtual crypto::tink::util::StatusOr<
      std::unique_ptr<crypto::tink::subtle::AeadOrDaead>>
  GetAeadOrDaead(const util::SecretData& seed) const = 0;

  // Return the key material size.
  virtual crypto::tink::util::StatusOr<uint32_t> GetKeyMaterialSize() const = 0;
};

}  // namespace tink
}  // namespace crypto

#endif  // THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_HYBRID_CECPQ2_AEAD_HKDF_DEM_HELPER_H_
