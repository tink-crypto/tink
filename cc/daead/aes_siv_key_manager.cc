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

#include "tink/daead/aes_siv_key_manager.h"

#include "absl/base/casts.h"
#include "absl/strings/string_view.h"
#include "tink/deterministic_aead.h"
#include "tink/key_manager.h"
#include "tink/subtle/aes_siv_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/aes_siv.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::AesSivKey;
using ::google::crypto::tink::AesSivKeyFormat;
using ::google::crypto::tink::KeyData;

class AesSivKeyFactory : public KeyFactoryBase<AesSivKey, AesSivKeyFormat> {
 public:
  AesSivKeyFactory() {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::SYMMETRIC;
  }

 protected:
  StatusOr<std::unique_ptr<AesSivKey>> NewKeyFromFormat(
      const AesSivKeyFormat& aes_siv_key_format) const override {
    Status status = AesSivKeyManager::Validate(aes_siv_key_format);
    if (!status.ok()) return status;

    auto aes_siv_key = absl::make_unique<AesSivKey>();
    aes_siv_key->set_version(AesSivKeyManager::kVersion);
    aes_siv_key->set_key_value(
        subtle::Random::GetRandomBytes(aes_siv_key_format.key_size()));
    return absl::implicit_cast<StatusOr<std::unique_ptr<AesSivKey>>>(
        std::move(aes_siv_key));
  }
};

constexpr uint32_t AesSivKeyManager::kVersion;

AesSivKeyManager::AesSivKeyManager()
    : key_factory_(absl::make_unique<AesSivKeyFactory>()) {}

uint32_t AesSivKeyManager::get_version() const { return kVersion; }

const KeyFactory& AesSivKeyManager::get_key_factory() const {
  return *key_factory_;
}

StatusOr<std::unique_ptr<DeterministicAead>>
AesSivKeyManager::GetPrimitiveFromKey(const AesSivKey& aes_siv_key) const {
  Status status = Validate(aes_siv_key);
  if (!status.ok()) return status;
  auto aes_siv_result = subtle::AesSivBoringSsl::New(aes_siv_key.key_value());
  if (!aes_siv_result.ok()) return aes_siv_result.status();
  return std::move(aes_siv_result.ValueOrDie());
}

// static
Status AesSivKeyManager::Validate(const AesSivKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;
  uint32_t key_size = key.key_value().size();
  if (key_size != 64) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid AesSivKey: key_value has %d bytes; "
                     "supported size: 64 bytes.",
                     key_size);
  }
  return Status::OK;
}

// static
Status AesSivKeyManager::Validate(const AesSivKeyFormat& key_format) {
  uint32_t key_size = key_format.key_size();
  if (key_size != 64) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid AesSivKeyFormat: key_size is %d bytes; "
                     "supported size: 64 bytes.",
                     key_size);
  }
  return Status::OK;
}

}  // namespace tink
}  // namespace crypto
