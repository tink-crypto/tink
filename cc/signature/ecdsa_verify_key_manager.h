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

#ifndef TINK_SIGNATURE_ECDSA_VERIFY_KEY_MANAGER_H_
#define TINK_SIGNATURE_ECDSA_VERIFY_KEY_MANAGER_H_

#include "absl/strings/string_view.h"
#include "cc/public_key_verify.h"
#include "cc/key_manager.h"
#include "cc/util/errors.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/message.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class EcdsaVerifyKeyManager : public KeyManager<PublicKeyVerify> {
 public:
  static constexpr char kKeyType[] =
      "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
  static constexpr uint32_t kVersion = 0;

  EcdsaVerifyKeyManager();

  // Constructs an instance of ECDSA PublicKeyVerify
  // for the given 'key_data', which must contain EcdsaPrivateKey-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<PublicKeyVerify>> GetPrimitive(
      const google::crypto::tink::KeyData& key_data) const override;

  // Constructs an instance of ECDSA PublicKeyVerify
  // for the given 'key', which must be EcdsaPrivateKey-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<PublicKeyVerify>>
  GetPrimitive(const google::protobuf::Message& key) const override;

  // Returns the type_url identifying the key type handled by this manager.
  const std::string& get_key_type() const override;

  // Returns the version of this key manager.
  uint32_t get_version() const override;

  // Returns a factory that generates keys of the key type
  // handled by this manager.
  const KeyFactory& get_key_factory() const override;

  virtual ~EcdsaVerifyKeyManager() {}

 private:
  friend class EcdsaSignKeyManager;
  static constexpr char kKeyTypePrefix[] = "type.googleapis.com/";
  static constexpr char kKeyFormatUrl[] =
      "type.googleapis.com/google.crypto.tink.EcdsaKeyFormat";

  std::string key_type_;
  std::unique_ptr<KeyFactory> key_factory_;

  // Constructs an instance of ECDSA PublicKeyVerify
  // for the given 'key'.
  crypto::tink::util::StatusOr<std::unique_ptr<PublicKeyVerify>>
      GetPrimitiveImpl(
          const google::crypto::tink::EcdsaPublicKey& ecdsa_public_key) const;

  static crypto::tink::util::Status Validate(
      const google::crypto::tink::EcdsaParams& params);
  static crypto::tink::util::Status Validate(
      const google::crypto::tink::EcdsaPublicKey& key);
  static crypto::tink::util::Status Validate(
      const google::crypto::tink::EcdsaKeyFormat& key_format);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_ECDSA_VERIFY_KEY_MANAGER_H_
