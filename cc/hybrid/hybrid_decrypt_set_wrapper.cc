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

#include "cc/hybrid/hybrid_decrypt_set_wrapper.h"

#include "cc/hybrid_decrypt.h"
#include "cc/crypto_format.h"
#include "cc/primitive_set.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"

namespace crypto {
namespace tink {

namespace {

util::Status Validate(PrimitiveSet<HybridDecrypt>* hybrid_decrypt_set) {
  if (hybrid_decrypt_set == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "hybrid_decrypt_set must be non-NULL");
  }
  if (hybrid_decrypt_set->get_primary() == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "hybrid_decrypt_set has no primary");
  }
  return util::Status::OK;
}

}  // anonymous namespace

// static
util::StatusOr<std::unique_ptr<HybridDecrypt>>
HybridDecryptSetWrapper::NewHybridDecrypt(
    std::unique_ptr<PrimitiveSet<HybridDecrypt>> hybrid_decrypt_set) {
  util::Status status = Validate(hybrid_decrypt_set.get());
  if (!status.ok()) return status;
  std::unique_ptr<HybridDecrypt> hybrid_decrypt(
      new HybridDecryptSetWrapper(std::move(hybrid_decrypt_set)));
  return std::move(hybrid_decrypt);
}

util::StatusOr<std::string> HybridDecryptSetWrapper::Decrypt(
    google::protobuf::StringPiece ciphertext,
    google::protobuf::StringPiece context_info) const {
  if (ciphertext.length() > CryptoFormat::kNonRawPrefixSize) {
    google::protobuf::StringPiece key_id = ciphertext.substr(0,
        CryptoFormat::kNonRawPrefixSize);
    auto primitives_result = hybrid_decrypt_set_->get_primitives(key_id);
    if (primitives_result.ok()) {
      google::protobuf::StringPiece raw_ciphertext =
          ciphertext.substr(CryptoFormat::kNonRawPrefixSize);
      for (auto& hybrid_decrypt_entry : *(primitives_result.ValueOrDie())) {
        HybridDecrypt& hybrid_decrypt = hybrid_decrypt_entry.get_primitive();
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
        HybridDecrypt& hybrid_decrypt = hybrid_decrypt_entry.get_primitive();
      auto decrypt_result = hybrid_decrypt.Decrypt(ciphertext, context_info);
      if (decrypt_result.ok()) {
        return std::move(decrypt_result.ValueOrDie());
      }
    }
  }
  return util::Status(util::error::INVALID_ARGUMENT, "decryption failed");
}

}  // namespace tink
}  // namespace crypto
