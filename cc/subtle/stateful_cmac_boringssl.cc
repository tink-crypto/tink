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

#include "tink/subtle/stateful_cmac_boringssl.h"

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "openssl/evp.h"
#include "tink/internal/aes_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

util::StatusOr<std::unique_ptr<StatefulMac>> StatefulCmacBoringSsl::New(
    uint32_t tag_size, const util::SecretData& key_value) {
  util::StatusOr<const EVP_CIPHER*> cipher =
      internal::GetAesCbcCipherForKeySize(key_value.size());
  if (!cipher.ok()) {
    return cipher.status();
  }
  if (tag_size > kMaxTagSize) {
    return util::Status(absl::StatusCode::kInvalidArgument, "invalid tag size");
  }

  // Create and initialize the CMAC context
  internal::SslUniquePtr<CMAC_CTX> ctx(CMAC_CTX_new());

  // Initialize the CMAC
  if (!CMAC_Init(ctx.get(), key_value.data(), key_value.size(), *cipher,
                 nullptr /* engine */)) {
    return util::Status(absl::StatusCode::kFailedPrecondition,
                        "CMAC initialization failed");
  }

  return {
      absl::WrapUnique(new StatefulCmacBoringSsl(tag_size, std::move(ctx)))};
}

util::Status StatefulCmacBoringSsl::Update(absl::string_view data) {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  if (!CMAC_Update(cmac_context_.get(),
                   reinterpret_cast<const uint8_t*>(data.data()),
                   data.size())) {
    return util::Status(absl::StatusCode::kInternal,
                        "Inputs to CMAC Update invalid");
  }
  return util::OkStatus();
}

util::StatusOr<std::string> StatefulCmacBoringSsl::Finalize() {
  uint8_t buf[EVP_MAX_MD_SIZE];
  size_t out_len;

  if (!CMAC_Final(cmac_context_.get(), buf, &out_len)) {
    return util::Status(absl::StatusCode::kInternal,
                        "CMAC finalization failed");
  }
  return std::string(reinterpret_cast<char*>(buf), tag_size_);
}

StatefulCmacBoringSslFactory::StatefulCmacBoringSslFactory(
    uint32_t tag_size, const util::SecretData& key_value)
    : tag_size_(tag_size), key_value_(key_value) {}

util::StatusOr<std::unique_ptr<StatefulMac>>
StatefulCmacBoringSslFactory::Create() const {
  return StatefulCmacBoringSsl::New(tag_size_, key_value_);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
