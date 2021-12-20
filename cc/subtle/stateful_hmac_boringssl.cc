// Copyright 2020 Google LLC
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

#include "tink/subtle/stateful_hmac_boringssl.h"

#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "openssl/evp.h"
#include "tink/internal/md_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace subtle {

util::StatusOr<std::unique_ptr<StatefulMac>> StatefulHmacBoringSsl::New(
    HashType hash_type, uint32_t tag_size, const util::SecretData& key_value) {
  util::StatusOr<const EVP_MD*> md = internal::EvpHashFromHashType(hash_type);
  if (!md.ok()) {
    return md.status();
  }
  if (EVP_MD_size(*md) < tag_size) {
    // The key manager is responsible to security policies.
    // The checks here just ensure the preconditions of the primitive.
    // If this fails then something is wrong with the key manager.
    return util::Status(absl::StatusCode::kInvalidArgument, "invalid tag size");
  }
  if (key_value.size() < kMinKeySize) {
    return util::Status(absl::StatusCode::kInvalidArgument, "invalid key size");
  }

  // Create and initialize the HMAC context
  internal::SslUniquePtr<HMAC_CTX> ctx(HMAC_CTX_new());
  // Initialize the HMAC
  if (!HMAC_Init(ctx.get(), key_value.data(), key_value.size(), *md)) {
    return util::Status(absl::StatusCode::kFailedPrecondition,
                        "HMAC initialization failed");
  }

  return std::unique_ptr<StatefulMac>(
      new StatefulHmacBoringSsl(tag_size, std::move(ctx)));
}

util::Status StatefulHmacBoringSsl::Update(absl::string_view data) {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  if (!HMAC_Update(hmac_context_.get(),
                   reinterpret_cast<const uint8_t*>(data.data()),
                   data.size())) {
    return util::Status(absl::StatusCode::kFailedPrecondition,
                        "Inputs to HMAC Update invalid");
  }
  return util::OkStatus();
}

util::StatusOr<std::string> StatefulHmacBoringSsl::Finalize() {
  uint8_t buf[EVP_MAX_MD_SIZE];
  unsigned int out_len;

  if (!HMAC_Final(hmac_context_.get(), buf, &out_len)) {
    return util::Status(absl::StatusCode::kInternal,
                        "HMAC finalization failed");
  }
  return std::string(reinterpret_cast<char*>(buf), tag_size_);
}

StatefulHmacBoringSslFactory::StatefulHmacBoringSslFactory(
    HashType hash_type, uint32_t tag_size, const util::SecretData& key_value)
    : hash_type_(hash_type), tag_size_(tag_size), key_value_(key_value) {}

util::StatusOr<std::unique_ptr<StatefulMac>>
StatefulHmacBoringSslFactory::Create() const {
  return StatefulHmacBoringSsl::New(hash_type_, tag_size_, key_value_);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
