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

#include "cc/hybrid/hybrid_encrypt_set_wrapper.h"

#include "cc/hybrid_encrypt.h"
#include "cc/crypto_format.h"
#include "cc/primitive_set.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"

namespace util = crypto::tink::util;

namespace crypto {
namespace tink {

namespace {

util::Status Validate(PrimitiveSet<HybridEncrypt>* hybrid_encrypt_set) {
  if (hybrid_encrypt_set == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "hybrid_encrypt_set must be non-NULL");
  }
  if (hybrid_encrypt_set->get_primary() == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "hybrid_encrypt_set has no primary");
  }
  return util::Status::OK;
}

}  // anonymous namespace

// static
util::StatusOr<std::unique_ptr<HybridEncrypt>>
HybridEncryptSetWrapper::NewHybridEncrypt(
    std::unique_ptr<PrimitiveSet<HybridEncrypt>> hybrid_encrypt_set) {
  util::Status status = Validate(hybrid_encrypt_set.get());
  if (!status.ok()) return status;
  std::unique_ptr<HybridEncrypt> hybrid_encrypt(
      new HybridEncryptSetWrapper(std::move(hybrid_encrypt_set)));
  return std::move(hybrid_encrypt);
}

util::StatusOr<std::string> HybridEncryptSetWrapper::Encrypt(
    google::protobuf::StringPiece plaintext,
    google::protobuf::StringPiece context_info) const {
  auto primary = hybrid_encrypt_set_->get_primary();
  auto encrypt_result =
      primary->get_primitive().Encrypt(plaintext, context_info);
  if (!encrypt_result.ok()) return encrypt_result.status();
  const std::string& key_id = primary->get_identifier();
  return key_id + encrypt_result.ValueOrDie();
}

}  // namespace tink
}  // namespace crypto
