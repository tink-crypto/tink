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

#include "tink/hybrid/hybrid_decrypt_wrapper.h"

#include "tink/crypto_format.h"
#include "tink/hybrid_decrypt.h"
#include "tink/primitive_set.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

namespace {

class HybridDecryptSetWrapper : public HybridDecrypt {
 public:
  explicit HybridDecryptSetWrapper(
      std::unique_ptr<PrimitiveSet<HybridDecrypt>> hybrid_decrypt_set)
      : hybrid_decrypt_set_(std::move(hybrid_decrypt_set)) {}

  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view context_info) const override;

  ~HybridDecryptSetWrapper() override {}

 private:
  std::unique_ptr<PrimitiveSet<HybridDecrypt>> hybrid_decrypt_set_;
};

util::StatusOr<std::string> HybridDecryptSetWrapper::Decrypt(
    absl::string_view ciphertext, absl::string_view context_info) const {
  // BoringSSL expects a non-null pointer for context_info,
  // regardless of whether the size is 0.
  context_info = subtle::SubtleUtilBoringSSL::EnsureNonNull(context_info);

  if (ciphertext.length() > CryptoFormat::kNonRawPrefixSize) {
    absl::string_view key_id =
        ciphertext.substr(0, CryptoFormat::kNonRawPrefixSize);
    auto primitives_result = hybrid_decrypt_set_->get_primitives(key_id);
    if (primitives_result.ok()) {
      absl::string_view raw_ciphertext =
          ciphertext.substr(CryptoFormat::kNonRawPrefixSize);
      for (auto& hybrid_decrypt_entry : *(primitives_result.ValueOrDie())) {
        HybridDecrypt& hybrid_decrypt = hybrid_decrypt_entry->get_primitive();
        auto decrypt_result =
            hybrid_decrypt.Decrypt(raw_ciphertext, context_info);
        if (decrypt_result.ok()) {
          return std::move(decrypt_result.ValueOrDie());
        } else {
          // LOG that a matching key didn't decrypt the ciphertext.
        }
      }
    }
  }

  // No matching key succeeded with decryption, try all RAW keys.
  auto raw_primitives_result = hybrid_decrypt_set_->get_raw_primitives();
  if (raw_primitives_result.ok()) {
    for (auto& hybrid_decrypt_entry : *(raw_primitives_result.ValueOrDie())) {
        HybridDecrypt& hybrid_decrypt = hybrid_decrypt_entry->get_primitive();
      auto decrypt_result = hybrid_decrypt.Decrypt(ciphertext, context_info);
      if (decrypt_result.ok()) {
        return std::move(decrypt_result.ValueOrDie());
      }
    }
  }
  return util::Status(util::error::INVALID_ARGUMENT, "decryption failed");
}

util::Status Validate(PrimitiveSet<HybridDecrypt>* hybrid_decrypt_set) {
  if (hybrid_decrypt_set == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "hybrid_decrypt_set must be non-NULL");
  }
  if (hybrid_decrypt_set->get_primary() == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "hybrid_decrypt_set has no primary");
  }
  return util::OkStatus();
}

}  // anonymous namespace

// static
util::StatusOr<std::unique_ptr<HybridDecrypt>>
HybridDecryptWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<HybridDecrypt>> primitive_set) const {
  util::Status status = Validate(primitive_set.get());
  if (!status.ok()) return status;
  std::unique_ptr<HybridDecrypt> hybrid_decrypt(
      new HybridDecryptSetWrapper(std::move(primitive_set)));
  return std::move(hybrid_decrypt);
}

}  // namespace tink
}  // namespace crypto
