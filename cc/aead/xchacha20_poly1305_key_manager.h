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

#include <algorithm>
#include <vector>

#ifndef TINK_AEAD_XCHACHA20_POLY1305_KEY_MANAGER_H_
#define TINK_AEAD_XCHACHA20_POLY1305_KEY_MANAGER_H_

#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/key_manager.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {

class XChaCha20Poly1305KeyManager : public KeyManager<Aead> {
 public:
  static constexpr char kKeyType[] =
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";
  static constexpr uint32_t kVersion = 0;

  XChaCha20Poly1305KeyManager();

  // Constructs an instance of XChacha20-Poly1305 Aead for the given
  // 'key_data', which must contain XChaCha20Poly1305Key-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<Aead>> GetPrimitive(
      const google::crypto::tink::KeyData& key_data) const override;

  // Constructs an instance of XChacha20-Poly1305 Aead for the given 'key',
  // which must be XChaCha20Poly1305Key-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<Aead>> GetPrimitive(
      const portable_proto::MessageLite& key) const override;

  // Returns the type_url identifying the key type handled by this manager.
  const std::string& get_key_type() const override;

  // Returns the version of this key manager.
  uint32_t get_version() const override;

  // Returns a factory that generates keys of the key type
  // handled by this manager.
  const KeyFactory& get_key_factory() const override;

  virtual ~XChaCha20Poly1305KeyManager() {}

 private:
  friend class XChaCha20Poly1305KeyFactory;

  static constexpr char kKeyTypePrefix[] = "type.googleapis.com/";

  std::string key_type_;
  std::unique_ptr<KeyFactory> key_factory_;

  // Constructs an instance of XChacha20-Poly1305 Aead for the given 'key'.
  crypto::tink::util::StatusOr<std::unique_ptr<Aead>> GetPrimitiveImpl(
      const google::crypto::tink::XChaCha20Poly1305Key& key) const;

  static crypto::tink::util::Status Validate(
      const google::crypto::tink::XChaCha20Poly1305Key& key);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_XCHACHA20_POLY1305_KEY_MANAGER_H_
