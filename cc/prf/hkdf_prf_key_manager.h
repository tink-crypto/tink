// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_PRF_HKDF_PRF_KEY_MANAGER_H_
#define TINK_PRF_HKDF_PRF_KEY_MANAGER_H_

#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/core/key_type_manager.h"
#include "tink/input_stream.h"
#include "tink/prf/prf_set.h"
#include "tink/subtle/prf/hkdf_streaming_prf.h"
#include "tink/subtle/prf/prf_set_util.h"
#include "tink/subtle/prf/streaming_prf.h"
#include "tink/subtle/random.h"
#include "tink/util/constants.h"
#include "tink/util/enums.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"
#include "proto/hkdf_prf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class HkdfPrfKeyManager
    : public KeyTypeManager<google::crypto::tink::HkdfPrfKey,
                            google::crypto::tink::HkdfPrfKeyFormat,
                            List<StreamingPrf, Prf>> {
 public:
  class StreamingPrfFactory : public PrimitiveFactory<StreamingPrf> {
    crypto::tink::util::StatusOr<std::unique_ptr<StreamingPrf>> Create(
        const google::crypto::tink::HkdfPrfKey& key) const override {
      return subtle::HkdfStreamingPrf::New(
          crypto::tink::util::Enums::ProtoToSubtle(key.params().hash()),
          util::SecretDataFromStringView(key.key_value()), key.params().salt());
    }
  };

  class PrfSetFactory : public PrimitiveFactory<Prf> {
    crypto::tink::util::StatusOr<std::unique_ptr<Prf>> Create(
        const google::crypto::tink::HkdfPrfKey& key) const override {
      auto hkdf_result = subtle::HkdfStreamingPrf::New(
          crypto::tink::util::Enums::ProtoToSubtle(key.params().hash()),
          util::SecretDataFromStringView(key.key_value()), key.params().salt());
      if (!hkdf_result.ok()) {
        return hkdf_result.status();
      }
      return subtle::CreatePrfFromStreamingPrf(
          std::move(hkdf_result.ValueOrDie()));
    }
  };

  HkdfPrfKeyManager()
      : KeyTypeManager(absl::make_unique<StreamingPrfFactory>(),
                       absl::make_unique<PrfSetFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::HkdfPrfKey& key) const override {
    crypto::tink::util::Status status =
        ValidateVersion(key.version(), get_version());
    if (!status.ok()) return status;
    status = ValidateKeySize(key.key_value().size());
    if (!status.ok()) return status;
    return ValidateParams(key.params());
  }

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::HkdfPrfKeyFormat& key_format) const override {
    crypto::tink::util::Status status =
        ValidateVersion(key_format.version(), get_version());
    if (!status.ok()) return status;
    status = ValidateKeySize(key_format.key_size());
    if (!status.ok()) return status;
    return ValidateParams(key_format.params());
  }

  crypto::tink::util::StatusOr<google::crypto::tink::HkdfPrfKey> CreateKey(
      const google::crypto::tink::HkdfPrfKeyFormat& key_format) const override {
    google::crypto::tink::HkdfPrfKey key;
    key.set_version(get_version());
    *key.mutable_params() = key_format.params();
    key.set_key_value(
        crypto::tink::subtle::Random::GetRandomBytes(key_format.key_size()));
    return key;
  }

  crypto::tink::util::StatusOr<google::crypto::tink::HkdfPrfKey> DeriveKey(
      const google::crypto::tink::HkdfPrfKeyFormat& key_format,
      InputStream* input_stream) const override {
    auto status = ValidateKeyFormat(key_format);
    if (!status.ok()) {
      return status;
    }
    crypto::tink::util::StatusOr<std::string> randomness =
        ReadBytesFromStream(key_format.key_size(), input_stream);
    if (!randomness.ok()) {
      return randomness.status();
    }
    google::crypto::tink::HkdfPrfKey key;
    key.set_version(get_version());
    *key.mutable_params() = key_format.params();
    key.set_key_value(randomness.ValueOrDie());
    return key;
  }

  FipsCompatibility FipsStatus() const override {
    return FipsCompatibility::kNotFips;
  }

 private:
  crypto::tink::util::Status ValidateKeySize(int key_size) const {
    if (key_size < kMinKeySizeBytes) {
      return crypto::tink::util::Status(
          util::error::INVALID_ARGUMENT,
          "Invalid HkdfPrfKey: key_value is too short.");
    }
    return crypto::tink::util::Status::OK;
  }

  crypto::tink::util::Status ValidateParams(
      const google::crypto::tink::HkdfPrfParams& params) const {
    // Omitting SHA1 for the moment; there seems to be no reason to allow it.
    if (params.hash() != google::crypto::tink::HashType::SHA256 &&
        params.hash() != google::crypto::tink::HashType::SHA512) {
      return crypto::tink::util::Status(
          util::error::INVALID_ARGUMENT,
          "Invalid HkdfPrfKey: unsupported hash.");
    }
    return crypto::tink::util::Status::OK;
  }

  // We use a somewhat larger minimum key size than usual, because PRFs might be
  // used by many users, in which case the security can degrade by a factor
  // depending on the number of users. (Discussed for example in
  // https://eprint.iacr.org/2012/159)
  const int kMinKeySizeBytes = 32;
  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom, google::crypto::tink::HkdfPrfKey().GetTypeName());
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRF_HKDF_PRF_KEY_MANAGER_H_
