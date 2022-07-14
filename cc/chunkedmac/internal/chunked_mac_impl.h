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

#ifndef TINK_CHUNKEDMAC_INTERNAL_CHUNKED_MAC_IMPL_H_
#define TINK_CHUNKEDMAC_INTERNAL_CHUNKED_MAC_IMPL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/chunked_mac.h"
#include "tink/subtle/mac/stateful_mac.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_cmac.pb.h"
#include "proto/hmac.pb.h"

namespace crypto {
namespace tink {
namespace internal {

class ChunkedMacComputationImpl : public ChunkedMacComputation {
 public:
  explicit ChunkedMacComputationImpl(
      std::unique_ptr<subtle::StatefulMac> stateful_mac)
      : stateful_mac_(std::move(stateful_mac)) {}

  util::Status Update(absl::string_view data) override;

  util::StatusOr<std::string> ComputeMac() override;

 private:
  const std::unique_ptr<subtle::StatefulMac> stateful_mac_;
  util::Status status_ = util::OkStatus();
};

class ChunkedMacVerificationImpl : public ChunkedMacVerification {
 public:
  explicit ChunkedMacVerificationImpl(
      std::unique_ptr<subtle::StatefulMac> stateful_mac, absl::string_view tag)
      : stateful_mac_(std::move(stateful_mac)), tag_(tag) {}

  util::Status Update(absl::string_view data) override;

  util::Status VerifyMac() override;

 private:
  const std::unique_ptr<subtle::StatefulMac> stateful_mac_;
  const std::string tag_;
  util::Status status_ = util::OkStatus();
};

class ChunkedMacImpl : public ChunkedMac {
 public:
  explicit ChunkedMacImpl(
      std::unique_ptr<subtle::StatefulMacFactory> stateful_mac_factory)
      : stateful_mac_factory_(std::move(stateful_mac_factory)) {}

  util::StatusOr<std::unique_ptr<ChunkedMacComputation>> CreateComputation()
      const override;

  util::StatusOr<std::unique_ptr<ChunkedMacVerification>> CreateVerification(
      absl::string_view tag) const override;

 private:
  std::unique_ptr<subtle::StatefulMacFactory> stateful_mac_factory_;
};

// Create new Chunked CMAC instance from `key`.
util::StatusOr<std::unique_ptr<ChunkedMac>> NewChunkedCmac(
    const google::crypto::tink::AesCmacKey& key);

// Create new Chunked HMAC instance from `key`.
util::StatusOr<std::unique_ptr<ChunkedMac>> NewChunkedHmac(
    const google::crypto::tink::HmacKey& key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_CHUNKEDMAC_INTERNAL_CHUNKED_MAC_IMPL_H_
