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

#ifndef TINK_SUBTLE_HMAC_BORINGSSL_H_
#define TINK_SUBTLE_HMAC_BORINGSSL_H_

#include <memory>

#include "cc/mac.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "openssl/evp.h"
#include "proto/common.pb.h"

namespace cloud {
namespace crypto {
namespace tink {

class HmacBoringSsl : public Mac {
 public:
  static util::StatusOr<std::unique_ptr<Mac>> New(
      google::cloud::crypto::tink::HashType hash_type,
      int tag_size, const std::string& key_value);

  // Computes and returns the HMAC for 'data'.
  util::StatusOr<std::string> ComputeMac(
      google::protobuf::StringPiece data) const override;

  // Verifies if 'mac' is a correct HMAC for 'data'.
  // Returns Status::OK if 'mac' is correct, and a non-OK-Status otherwise.
  util::Status VerifyMac(
      google::protobuf::StringPiece mac,
      google::protobuf::StringPiece data) const override;

  virtual ~HmacBoringSsl() {}

 private:
  HmacBoringSsl() {}
  HmacBoringSsl(const EVP_MD* md, int tag_size, const std::string& key_value);

  // HmacBoringSsl is not owner of md (it is owned by BoringSSL).
  const EVP_MD* md_;
  int tag_size_;
  std::string key_value_;
};

}  // namespace tink
}  // namespace crypto
}  // namespace cloud

#endif  // TINK_SUBTLE_HMAC_BORINGSSL_H_
