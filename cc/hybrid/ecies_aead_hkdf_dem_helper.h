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

#include "absl/strings/string_view.h"
#include "cc/aead.h"
#include "cc/key_manager.h"
#include "cc/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// A helper for DEM (data encapsulation mechanism) of ECIES-AEAD-HKDF.
// TODO(przydatek):  add a _test.cc-file for this class.
class EciesAeadHkdfDemHelper {
 public:
  // Constructs a new helper for the specified DEM key template.
  static crypto::tink::util::StatusOr<std::unique_ptr<EciesAeadHkdfDemHelper>>
      New(const google::crypto::tink::KeyTemplate& dem_key_template);

  // Returns the size of the DEM-key in bytes.
  uint32_t dem_key_size_in_bytes() {
    return dem_key_size_in_bytes_;
  }

  // Creates and returns a new Aead-primitive that uses
  // the key material given in 'symmetric_key', which must
  // be of length dem_key_size_in_bytes().
  crypto::tink::util::StatusOr<std::unique_ptr<Aead>> GetAead(
      const std::string& symmetric_key_value) const;

 private:
  enum DemKeyType {
    UNKNOWN_KEY = 0,
    AES_GCM_KEY,
    AES_CTR_HMAC_AEAD_KEY,
  };

  EciesAeadHkdfDemHelper(
      const google::crypto::tink::KeyTemplate& dem_key_template)
      : dem_key_template_(dem_key_template) {}

  bool ReplaceKeyBytes(const std::string& key_bytes,
                       google::protobuf::Message* key) const;

  google::crypto::tink::KeyTemplate dem_key_template_;
  DemKeyType dem_key_type_;
  uint32_t dem_key_size_in_bytes_;
  uint32_t aes_ctr_key_size_in_bytes_ = 0;
  const KeyManager<Aead>* dem_key_manager_;  // not owned
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_ECIES_AEAD_HKDF_DEM_HELPER_H_
