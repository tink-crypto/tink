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

#ifndef TINK_AEAD_AES_EAX_KEY_MANAGER_H_
#define TINK_AEAD_AES_EAX_KEY_MANAGER_H_

#include <algorithm>
#include <vector>

#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/key_manager.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_eax.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class AesEaxKeyManager : public KeyManager<Aead> {
 public:
  static constexpr char kKeyType[] =
      "type.googleapis.com/google.crypto.tink.AesEaxKey";
  static constexpr uint32_t kVersion = 0;

  AesEaxKeyManager();

  // Constructs an instance of AES-EAX Aead for the given 'key_data',
  // which must contain AesEaxKey-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<Aead>> GetPrimitive(
      const google::crypto::tink::KeyData& key_data) const override;

  // Constructs an instance of AES-EAX Aead for the given 'key',
  // which must be AesEaxKey-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<Aead>>
  GetPrimitive(const portable_proto::MessageLite& key) const override;

  // Returns the type_url identifying the key type handled by this manager.
  const std::string& get_key_type() const override;

  // Returns the version of this key manager.
  uint32_t get_version() const override;

  // Returns a factory that generates keys of the key type
  // handled by this manager.
  const KeyFactory& get_key_factory() const override;

  virtual ~AesEaxKeyManager() {}

 private:
  friend class AesEaxKeyFactory;

  static constexpr char kKeyTypePrefix[] = "type.googleapis.com/";
  static constexpr char kKeyFormatUrl[] =
      "type.googleapis.com/google.crypto.tink.AesEaxKeyFormat";

  std::string key_type_;
  std::unique_ptr<KeyFactory> key_factory_;

  // Constructs an instance of AES-EAX Aead for the given 'key'.
  crypto::tink::util::StatusOr<std::unique_ptr<Aead>>
  GetPrimitiveImpl(const google::crypto::tink::AesEaxKey& aes_eax_key) const;

  static crypto::tink::util::Status Validate(
      const google::crypto::tink::AesEaxKey& key);
  static crypto::tink::util::Status Validate(
      const google::crypto::tink::AesEaxKeyFormat& key_format);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_AES_EAX_KEY_MANAGER_H_
