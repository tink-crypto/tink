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

#include "tink/aead/aes_eax_key_manager.h"

#include "absl/base/casts.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/key_manager.h"
#include "tink/subtle/aes_eax_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/aes_eax.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::AesEaxKey;
using google::crypto::tink::AesEaxKeyFormat;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyTemplate;
using portable_proto::MessageLite;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

class AesEaxKeyFactory : public KeyFactoryBase<AesEaxKey, AesEaxKeyFormat> {
 public:
  AesEaxKeyFactory() {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::SYMMETRIC;
  }

 protected:
  StatusOr<std::unique_ptr<AesEaxKey>> NewKeyFromFormat(
      const AesEaxKeyFormat& aes_eax_key_format) const override {
    Status status = AesEaxKeyManager::Validate(aes_eax_key_format);
    if (!status.ok()) return status;

    auto aes_eax_key = absl::make_unique<AesEaxKey>();
    aes_eax_key->set_version(AesEaxKeyManager::kVersion);
    aes_eax_key->set_key_value(
        subtle::Random::GetRandomBytes(aes_eax_key_format.key_size()));
    aes_eax_key->mutable_params()->set_iv_size(
        aes_eax_key_format.params().iv_size());
    return absl::implicit_cast<StatusOr<std::unique_ptr<AesEaxKey>>>(
        std::move(aes_eax_key));
  }
};

constexpr uint32_t AesEaxKeyManager::kVersion;

AesEaxKeyManager::AesEaxKeyManager()
    : key_factory_(absl::make_unique<AesEaxKeyFactory>()) {}

uint32_t AesEaxKeyManager::get_version() const {
  return kVersion;
}

const KeyFactory& AesEaxKeyManager::get_key_factory() const {
  return *key_factory_;
}

StatusOr<std::unique_ptr<Aead>> AesEaxKeyManager::GetPrimitiveFromKey(
    const AesEaxKey& aes_eax_key) const {
  Status status = Validate(aes_eax_key);
  if (!status.ok()) return status;
  auto aes_eax_result = subtle::AesEaxBoringSsl::New(
      aes_eax_key.key_value(), aes_eax_key.params().iv_size());
  if (!aes_eax_result.ok()) return aes_eax_result.status();
  return std::move(aes_eax_result.ValueOrDie());
}

// static
Status AesEaxKeyManager::Validate(const AesEaxKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;
  uint32_t key_size = key.key_value().size();
  if (key_size != 16 && key_size != 32) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid AesEaxKey: key_value has %d bytes; "
                       "supported sizes: 16 or 32 bytes.", key_size);
  }
  uint32_t iv_size = key.params().iv_size();
  if (iv_size != 12 && iv_size != 16) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid AesEaxKey: iv_size is %d bytes; "
                       "supported sizes: 12 or 16 bytes.", iv_size);
  }
  return Status::OK;
}

// static
Status AesEaxKeyManager::Validate(const AesEaxKeyFormat& key_format) {
  uint32_t key_size = key_format.key_size();
  if (key_size != 16 && key_size != 32) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid AesEaxKeyFormat: key_size is %d bytes; "
                       "supported sizes: 16 or 32 bytes.", key_size);
  }
  uint32_t iv_size = key_format.params().iv_size();
  if (iv_size != 12 && iv_size != 16) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid AesEaxKeyFormat: iv_size is %d bytes; "
                       "supported sizes: 12 or 16 bytes.", iv_size);
  }
  return Status::OK;
}

}  // namespace tink
}  // namespace crypto
