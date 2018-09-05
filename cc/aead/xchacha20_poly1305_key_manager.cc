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

class XChaCha20Poly1305KeyFactory : public KeyFactory {
 public:
  XChaCha20Poly1305KeyFactory() {}

  // Generates a new random XChaCha20Poly1305Key. XChaCha20Poly1305 does not
  // need any key format, thus |key_format| is ignored.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(const portable_proto::MessageLite& key_format) const override;

  // Generates a new random XChaCha20Poly1305Key. XChaCha20Poly1305 does not
  // need any key format, thus |serialized_key_format| is ignored.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(absl::string_view serialized_key_format) const override;

  // Generates a new random XChaCha20Poly1305Key, and wraps it in a
  // KeyData-proto. XChaCha20Poly1305 does not need any key format, thus
  // |serialized_key_format| is ignored.
  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(absl::string_view serialized_key_format) const override;

 private:
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey() const;
};

StatusOr<std::unique_ptr<MessageLite>> XChaCha20Poly1305KeyFactory::NewKey()
    const {
  // Generate XChaCha20Poly1305Key.
  std::unique_ptr<XChaCha20Poly1305Key> xchacha20_poly1305_key(
      new XChaCha20Poly1305Key());
  xchacha20_poly1305_key->set_version(XChaCha20Poly1305KeyManager::kVersion);
  xchacha20_poly1305_key->set_key_value(
      subtle::Random::GetRandomBytes(kKeySizeInBytes));
  std::unique_ptr<MessageLite> key = std::move(xchacha20_poly1305_key);
  return std::move(key);
}

StatusOr<std::unique_ptr<MessageLite>> XChaCha20Poly1305KeyFactory::NewKey(
    const portable_proto::MessageLite& key_format) const {
  return NewKey();
}

StatusOr<std::unique_ptr<MessageLite>> XChaCha20Poly1305KeyFactory::NewKey(
    absl::string_view serialized_key_format) const {
  return NewKey();
}

StatusOr<std::unique_ptr<KeyData>> XChaCha20Poly1305KeyFactory::NewKeyData(
    absl::string_view serialized_key_format) const {
  auto new_key_result = NewKey();
  if (!new_key_result.ok()) return new_key_result.status();
  auto new_key = reinterpret_cast<const XChaCha20Poly1305Key&>(
      *(new_key_result.ValueOrDie()));
  std::unique_ptr<KeyData> key_data(new KeyData());
  key_data->set_type_url(XChaCha20Poly1305KeyManager::kKeyType);
  key_data->set_value(new_key.SerializeAsString());
  key_data->set_key_material_type(KeyData::SYMMETRIC);
  return std::move(key_data);
}

constexpr char XChaCha20Poly1305KeyManager::kKeyTypePrefix[];
constexpr char XChaCha20Poly1305KeyManager::kKeyType[];
constexpr uint32_t XChaCha20Poly1305KeyManager::kVersion;

XChaCha20Poly1305KeyManager::XChaCha20Poly1305KeyManager()
    : key_type_(kKeyType), key_factory_(new XChaCha20Poly1305KeyFactory()) {}

const std::string& XChaCha20Poly1305KeyManager::get_key_type() const {
  return key_type_;
}

uint32_t XChaCha20Poly1305KeyManager::get_version() const { return kVersion; }

const KeyFactory& XChaCha20Poly1305KeyManager::get_key_factory() const {
  return *key_factory_;
}

StatusOr<std::unique_ptr<Aead>> XChaCha20Poly1305KeyManager::GetPrimitive(
    const KeyData& key_data) const {
  if (DoesSupport(key_data.type_url())) {
    XChaCha20Poly1305Key xchacha20_poly1305_key;
    if (!xchacha20_poly1305_key.ParseFromString(key_data.value())) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Could not parse key_data.value as key type '%s'.",
                       key_data.type_url().c_str());
    }
    return GetPrimitiveImpl(xchacha20_poly1305_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_data.type_url().c_str());
  }
}

StatusOr<std::unique_ptr<Aead>> XChaCha20Poly1305KeyManager::GetPrimitive(
    const MessageLite& key) const {
  std::string key_type = std::string(kKeyTypePrefix) + key.GetTypeName();
  if (DoesSupport(key_type)) {
    const XChaCha20Poly1305Key& xchacha20_poly1305_key =
        reinterpret_cast<const XChaCha20Poly1305Key&>(key);
    return GetPrimitiveImpl(xchacha20_poly1305_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_type.c_str());
  }
}

StatusOr<std::unique_ptr<Aead>> XChaCha20Poly1305KeyManager::GetPrimitiveImpl(
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
