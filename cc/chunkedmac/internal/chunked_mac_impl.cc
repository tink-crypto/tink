// Copyright 2022 Google LLC
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

#include "tink/chunkedmac/internal/chunked_mac_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "openssl/mem.h"
#include "tink/chunked_mac.h"
#include "tink/subtle/mac/stateful_mac.h"
#include "tink/subtle/stateful_cmac_boringssl.h"
#include "tink/subtle/stateful_hmac_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_cmac.pb.h"
#include "proto/hmac.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using ::google::crypto::tink::AesCmacKey;
using ::google::crypto::tink::HmacKey;

util::Status ChunkedMacComputationImpl::Update(absl::string_view data) {
  if (!status_.ok()) return status_;
  return stateful_mac_->Update(data);
}

util::StatusOr<std::string> ChunkedMacComputationImpl::ComputeMac() {
  if (!status_.ok()) return status_;
  status_ = util::Status(absl::StatusCode::kFailedPrecondition,
                         "MAC computation already finalized.");
  return stateful_mac_->Finalize();
}

util::Status ChunkedMacVerificationImpl::Update(absl::string_view data) {
  if (!status_.ok()) return status_;
  return stateful_mac_->Update(data);
}

util::Status ChunkedMacVerificationImpl::VerifyMac() {
  if (!status_.ok()) return status_;
  status_ = util::Status(absl::StatusCode::kFailedPrecondition,
                         "MAC verification already finalized.");
  util::StatusOr<std::string> computed_mac = stateful_mac_->Finalize();
  if (!computed_mac.ok()) {
    return computed_mac.status();
  }
  if (computed_mac->size() != tag_.size()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Verification failed.");
  }
  if (CRYPTO_memcmp(computed_mac->data(), tag_.data(), computed_mac->size())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Verification failed.");
  }
  return util::OkStatus();
}

util::StatusOr<std::unique_ptr<ChunkedMacComputation>>
ChunkedMacImpl::CreateComputation() const {
  util::StatusOr<std::unique_ptr<subtle::StatefulMac>> stateful_mac =
      stateful_mac_factory_->Create();
  if (!stateful_mac.ok()) return stateful_mac.status();

  return std::unique_ptr<ChunkedMacComputation>(
      new ChunkedMacComputationImpl(*std::move(stateful_mac)));
}

util::StatusOr<std::unique_ptr<ChunkedMacVerification>>
ChunkedMacImpl::CreateVerification(absl::string_view tag) const {
  util::StatusOr<std::unique_ptr<subtle::StatefulMac>> stateful_mac =
      stateful_mac_factory_->Create();
  if (!stateful_mac.ok()) return stateful_mac.status();

  return std::unique_ptr<ChunkedMacVerification>(
      new ChunkedMacVerificationImpl(*std::move(stateful_mac), tag));
}

util::StatusOr<std::unique_ptr<ChunkedMac>> NewChunkedCmac(
    const AesCmacKey& key) {
  if (!key.has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid key: missing parameters.");
  }
  util::SecretData secret_key_data =
      util::SecretDataFromStringView(key.key_value());
  auto stateful_mac_factory =
      absl::make_unique<subtle::StatefulCmacBoringSslFactory>(
          key.params().tag_size(), secret_key_data);
  return std::unique_ptr<ChunkedMac>(
      new ChunkedMacImpl(std::move(stateful_mac_factory)));
}

util::StatusOr<std::unique_ptr<ChunkedMac>> NewChunkedHmac(const HmacKey& key) {
  if (!key.has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid key: missing paramaters.");
  }
  subtle::HashType hash_type = util::Enums::ProtoToSubtle(key.params().hash());
  util::SecretData secret_key_data =
      util::SecretDataFromStringView(key.key_value());
  auto stateful_mac_factory =
      absl::make_unique<subtle::StatefulHmacBoringSslFactory>(
          hash_type, key.params().tag_size(), secret_key_data);
  return std::unique_ptr<ChunkedMac>(
      new ChunkedMacImpl(std::move(stateful_mac_factory)));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
