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

#include "tink/aead/xchacha20_poly1305_key_manager.h"

#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/key_manager.h"
#include "tink/subtle/random.h"
#include "tink/subtle/xchacha20_poly1305_boringssl.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/empty.pb.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::KeyData;
using google::crypto::tink::XChaCha20Poly1305Key;
using portable_proto::MessageLite;

const int kKeySizeInBytes = 32;

class XChaCha20Poly1305KeyFactory
    : public KeyFactoryBase<XChaCha20Poly1305Key, google::crypto::tink::Empty> {
 public:
  XChaCha20Poly1305KeyFactory() {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::SYMMETRIC;
  }

 protected:
  StatusOr<std::unique_ptr<XChaCha20Poly1305Key>> NewKeyFromFormat(
      const google::crypto::tink::Empty&) const override {
    auto xchacha20_poly1305_key = absl::make_unique<XChaCha20Poly1305Key>();
    xchacha20_poly1305_key->set_version(XChaCha20Poly1305KeyManager::kVersion);
    xchacha20_poly1305_key->set_key_value(
        subtle::Random::GetRandomBytes(kKeySizeInBytes));
    return std::move(xchacha20_poly1305_key);
  }
};

constexpr uint32_t XChaCha20Poly1305KeyManager::kVersion;

XChaCha20Poly1305KeyManager::XChaCha20Poly1305KeyManager()
    : key_factory_(absl::make_unique<XChaCha20Poly1305KeyFactory>()) {}

uint32_t XChaCha20Poly1305KeyManager::get_version() const { return kVersion; }

const KeyFactory& XChaCha20Poly1305KeyManager::get_key_factory() const {
  return *key_factory_;
}

StatusOr<std::unique_ptr<Aead>>
XChaCha20Poly1305KeyManager::GetPrimitiveFromKey(
    const XChaCha20Poly1305Key& xchacha20_poly1305_key) const {
  Status status = Validate(xchacha20_poly1305_key);
  if (!status.ok()) return status;
  auto xchacha20_poly1305_result = subtle::XChacha20Poly1305BoringSsl::New(
      xchacha20_poly1305_key.key_value());
  if (!xchacha20_poly1305_result.ok())
    return xchacha20_poly1305_result.status();
  return std::move(xchacha20_poly1305_result.ValueOrDie());
}

// static
Status XChaCha20Poly1305KeyManager::Validate(const XChaCha20Poly1305Key& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;
  uint32_t key_size = key.key_value().size();
  if (key_size != 32) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid XChaCha20Poly1305Key: key_value has %d bytes; "
                     "supported size: 32 bytes.",
                     key_size);
  }
  return Status::OK;
}

}  // namespace tink
}  // namespace crypto
