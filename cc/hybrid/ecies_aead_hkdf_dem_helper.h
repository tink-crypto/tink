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

#ifndef TINK_HYBRID_ECIES_AEAD_HKDF_DEM_HELPER_H_
#define TINK_HYBRID_ECIES_AEAD_HKDF_DEM_HELPER_H_

#include <memory>

#include "tink/aead.h"
#include "tink/daead/subtle/aead_or_daead.h"
#include "tink/key_manager.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// A helper for DEM (data encapsulation mechanism) of ECIES-AEAD-HKDF.
class EciesAeadHkdfDemHelper {
 public:
  // Constructs a new helper for the specified DEM key template.
  static
  crypto::tink::util::StatusOr<std::unique_ptr<const EciesAeadHkdfDemHelper>>
      New(const google::crypto::tink::KeyTemplate& dem_key_template);

  virtual ~EciesAeadHkdfDemHelper() {}

  // Returns the size of the DEM-key in bytes.
  uint32_t dem_key_size_in_bytes() const {
    return key_params_.key_size_in_bytes;
  }

  // Creates and returns a new AeadOrDaead object that uses
  // the key material given in 'symmetric_key', which must
  // be of length dem_key_size_in_bytes().
  virtual crypto::tink::util::StatusOr<
      std::unique_ptr<crypto::tink::subtle::AeadOrDaead>>
  GetAeadOrDaead(const util::SecretData& symmetric_key_value) const = 0;

 protected:
  enum DemKeyType {
    AES_GCM_KEY,
    AES_CTR_HMAC_AEAD_KEY,
    XCHACHA20_POLY1305_KEY,
    AES_SIV_KEY,
  };

  struct DemKeyParams {
    DemKeyType key_type;
    uint32_t key_size_in_bytes;
    uint32_t aes_ctr_key_size_in_bytes;
  };

  EciesAeadHkdfDemHelper(const google::crypto::tink::KeyTemplate& key_template,
                         DemKeyParams key_params)
      : key_template_(key_template), key_params_(key_params) {}

  static util::StatusOr<DemKeyParams> GetKeyParams(
      const ::google::crypto::tink::KeyTemplate& key_template);

  bool ReplaceKeyBytes(const util::SecretData& key_bytes,
                       portable_proto::MessageLite* proto) const;

  void ZeroKeyBytes(portable_proto::MessageLite* proto) const;

  const google::crypto::tink::KeyTemplate key_template_;
  const DemKeyParams key_params_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_ECIES_AEAD_HKDF_DEM_HELPER_H_
