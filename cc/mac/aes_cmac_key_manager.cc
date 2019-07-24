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

#include "tink/mac/aes_cmac_key_manager.h"

#include <map>

#include "absl/strings/string_view.h"
#include "tink/key_manager.h"
#include "tink/mac.h"
#include "tink/subtle/aes_cmac_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/aes_cmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Enums;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::AesCmacKey;
using google::crypto::tink::AesCmacKeyFormat;
using google::crypto::tink::AesCmacParams;
using google::crypto::tink::KeyData;

constexpr uint32_t AesCmacKeyManager::kVersion;
// Due to https://www.math.uwaterloo.ca/~ajmeneze/publications/tightness.pdf, we
// only allow key sizes of 256 bit.
constexpr int kKeySizeInBytes = 32;
constexpr int kMaxTagSizeInBytes = 16;
constexpr int kMinTagSizeInBytes = 10;

class AesCmacKeyFactory : public KeyFactoryBase<AesCmacKey, AesCmacKeyFormat> {
 public:
  AesCmacKeyFactory() {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::SYMMETRIC;
  }

 protected:
  StatusOr<std::unique_ptr<AesCmacKey>> NewKeyFromFormat(
      const AesCmacKeyFormat& cmac_key_format) const override;
};

StatusOr<std::unique_ptr<AesCmacKey>> AesCmacKeyFactory::NewKeyFromFormat(
    const AesCmacKeyFormat& cmac_key_format) const {
  Status status = AesCmacKeyManager::Validate(cmac_key_format);
  if (!status.ok()) return status;
  auto cmac_key = absl::make_unique<AesCmacKey>();
  cmac_key->set_version(AesCmacKeyManager::kVersion);
  cmac_key->set_key_value(
      subtle::Random::GetRandomBytes(cmac_key_format.key_size()));
  *cmac_key->mutable_params() = cmac_key_format.params();
  return absl::implicit_cast<StatusOr<std::unique_ptr<AesCmacKey>>>(
      std::move(cmac_key));
}

AesCmacKeyManager::AesCmacKeyManager()
    : key_factory_(new AesCmacKeyFactory()) {}

uint32_t AesCmacKeyManager::get_version() const { return kVersion; }

const KeyFactory& AesCmacKeyManager::get_key_factory() const {
  return *key_factory_;
}

StatusOr<std::unique_ptr<Mac>> AesCmacKeyManager::GetPrimitiveFromKey(
    const AesCmacKey& cmac_key) const {
  Status status = Validate(cmac_key);
  if (!status.ok()) return status;
  auto cmac_result = subtle::AesCmacBoringSsl::New(
      cmac_key.key_value(), cmac_key.params().tag_size());
  if (!cmac_result.ok()) return cmac_result.status();
  return std::move(cmac_result.ValueOrDie());
}

// static
Status AesCmacKeyManager::Validate(const AesCmacParams& params) {
  if (params.tag_size() < kMinTagSizeInBytes) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid AesCmacParams: tag_size %d is too small.",
                     params.tag_size());
  }
  if (params.tag_size() > kMaxTagSizeInBytes) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid AesCmacParams: tag_size %d is too big.",
                     params.tag_size());
  }
  return Status::OK;
}

// static
Status AesCmacKeyManager::Validate(const AesCmacKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;
  if (key.key_value().size() != kKeySizeInBytes) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid AesCmacKey: key_value wrong length.");
  }
  return Validate(key.params());
}

// static
Status AesCmacKeyManager::Validate(const AesCmacKeyFormat& key_format) {
  if (key_format.key_size() != kKeySizeInBytes) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid AesCmacKeyFormat: invalid key_size.");
  }
  return Validate(key_format.params());
}

}  // namespace tink
}  // namespace crypto
