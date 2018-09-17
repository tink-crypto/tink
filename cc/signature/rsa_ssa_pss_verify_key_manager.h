// Copyright 2018 Google Inc.
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
#ifndef THIRD_PARTY_TINK_CC_SIGNATURE_RSA_SSA_PSS_VERIFY_KEY_MANAGER_H_
#define THIRD_PARTY_TINK_CC_SIGNATURE_RSA_SSA_PSS_VERIFY_KEY_MANAGER_H_

#include <algorithm>
#include <vector>

#include "absl/strings/string_view.h"
#include "tink/core/key_manager_base.h"
#include "tink/key_manager.h"
#include "tink/public_key_verify.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class RsaSsaPssVerifyKeyManager
    : public KeyManagerBase<PublicKeyVerify,
                            google::crypto::tink::RsaSsaPssPublicKey> {
 public:
  static constexpr char kKeyType[] =
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey";
  static constexpr uint32_t kVersion = 0;

  RsaSsaPssVerifyKeyManager();

  // Returns the type_url identifying the key type handled by this manager.
  const std::string& get_key_type() const override;

  // Returns the version of this key manager.
  uint32_t get_version() const override;

  // Returns a factory that generates keys of the key type
  // handled by this manager.
  const KeyFactory& get_key_factory() const override;

  virtual ~RsaSsaPssVerifyKeyManager() {}

 protected:
  crypto::tink::util::StatusOr<std::unique_ptr<PublicKeyVerify>>
  GetPrimitiveFromKey(const google::crypto::tink::RsaSsaPssPublicKey&
                          rsa_ssa_pss_public_key) const override;

 private:
  // To reach 128-bit security strength, RSA's modulus must be at least 3072-bit
  // while 2048-bit RSA key only has 112-bit security. Nevertheless, a 2048-bit
  // RSA key is considered safe by NIST until 2030 (see
  // https://www.keylength.com/en/4/).
  static const size_t kMinModulusSizeInBits = 2048;
  static constexpr char kKeyTypePrefix[] = "type.googleapis.com/";
  static constexpr char kKeyFormatUrl[] =
      "type.googleapis.com/google.crypto.tink.RsaSsaPssKeyFormat";

  std::string key_type_;
  std::unique_ptr<KeyFactory> key_factory_;

  static crypto::tink::util::Status Validate(
      const google::crypto::tink::RsaSsaPssParams& params);
  static crypto::tink::util::Status Validate(
      const google::crypto::tink::RsaSsaPssPublicKey& key);
  static crypto::tink::util::Status Validate(
      const google::crypto::tink::RsaSsaPssKeyFormat& key_format);
};

}  // namespace tink
}  // namespace crypto

#endif  // THIRD_PARTY_TINK_CC_SIGNATURE_RSA_SSA_PSS_VERIFY_KEY_MANAGER_H_
