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

#include <algorithm>
#include <vector>

#ifndef TINK_HYBRID_ECIES_AEAD_HKDF_PRIVATE_KEY_MANAGER_H_
#define TINK_HYBRID_ECIES_AEAD_HKDF_PRIVATE_KEY_MANAGER_H_

#include "cc/hybrid_decrypt.h"
#include "cc/key_manager.h"
#include "cc/util/errors.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/message.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class EciesAeadHkdfPrivateKeyManager : public KeyManager<HybridDecrypt> {
 public:
  static constexpr char kKeyType[] =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";

  EciesAeadHkdfPrivateKeyManager() : key_type_(kKeyType) {}

  // Constructs an instance of ECIES-AEAD-HKDF HybridDecrypt
  // for the given 'key_data', which must contain EciesAeadHkdfPrivateKey-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<HybridDecrypt>> GetPrimitive(
      const google::crypto::tink::KeyData& key_data) const override;

  // Constructs an instance of ECIES-AEAD-HKDF HybridDecrypt
  // for the given 'key', which must be EciesAeadHkdfPrivateKey-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<HybridDecrypt>>
  GetPrimitive(const google::protobuf::Message& key) const override;

  // Generates a new random EciesAeadHkdfPrivateKey, based on
  // the given 'key_template', which must contain EciesAeadHkdfKeyFormat-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<google::protobuf::Message>>
      NewKey(const google::crypto::tink::KeyTemplate& key_template)
      const override;

  // Returns the type_url identifying the key type handled by this manager.
  const std::string& get_key_type() const override;

  // Returns the version of this key manager.
  uint32_t get_version() const override;

  virtual ~EciesAeadHkdfPrivateKeyManager() {}

 private:
  static constexpr char kKeyTypePrefix[] = "type.googleapis.com/";

  std::string key_type_;

  // Constructs an instance of ECIES-AEAD-HKDF HybridDecrypt
  // for the given 'key'.
  crypto::tink::util::StatusOr<std::unique_ptr<HybridDecrypt>> GetPrimitiveImpl(
      const google::crypto::tink::EciesAeadHkdfPrivateKey& ecies_private_key) const;

  crypto::tink::util::Status Validate(
      const google::crypto::tink::EciesAeadHkdfParams& params) const;
  crypto::tink::util::Status Validate(
      const google::crypto::tink::EciesAeadHkdfPrivateKey& key) const;
  crypto::tink::util::Status Validate(
      const google::crypto::tink::EciesAeadHkdfKeyFormat& key_format) const;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_ECIES_AEAD_HKDF_PUBLIC_KEY_MANAGER_H_
