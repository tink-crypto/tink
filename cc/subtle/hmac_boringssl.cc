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

#include "cc/subtle/hmac_boringssl.h"

#include <string>

#include "cc/mac.h"
#include "cc/subtle/subtle_util_boringssl.h"
#include "cc/util/errors.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "openssl/digest.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "proto/common.pb.h"
using google::crypto::tink::HashType;

namespace crypto {
namespace tink {

// static
util::StatusOr<std::unique_ptr<Mac>> HmacBoringSsl::New(
    HashType hash_type, uint32_t tag_size, const std::string& key_value) {
  util::StatusOr<const EVP_MD*> res = SubtleUtilBoringSSL::EvpHash(hash_type);
  if (!res.ok()) {
    return res.status();
  }
  const EVP_MD* md = res.ValueOrDie();
  if (EVP_MD_size(md) < tag_size) {
    // The key manager is responsible to security policies.
    // The checks here just ensure the preconditions of the primitive.
    // If this fails then something is wrong with the key manager.
    return util::Status(util::error::INTERNAL, "invalid tag size");
  }
  std::unique_ptr<Mac> hmac(new HmacBoringSsl(md, tag_size, key_value));
  return std::move(hmac);
}

HmacBoringSsl::HmacBoringSsl(const EVP_MD* md, uint32_t tag_size,
                             const std::string& key_value)
    : md_(md), tag_size_(tag_size), key_value_(key_value) {}

util::StatusOr<std::string> HmacBoringSsl::ComputeMac(
    google::protobuf::StringPiece data) const {
  uint8_t buf[EVP_MAX_MD_SIZE];
  unsigned int out_len;
  const uint8_t* res = HMAC(md_, key_value_.data(), key_value_.size(),
                            reinterpret_cast<const uint8_t*>(data.data()),
                            data.size(), buf, &out_len);
  if (res == nullptr) {
    // TODO(bleichen): We expect that BoringSSL supports the
    //   hashes that we use. Maybe we should have a status that indicates
    //   such mismatches between expected and actual behaviour.
    return util::Status(util::error::INTERNAL,
                        "BoringSSL failed to compute HMAC");
  }
  return std::string(reinterpret_cast<char*>(buf), tag_size_);
}

util::Status HmacBoringSsl::VerifyMac(
    google::protobuf::StringPiece mac,
    google::protobuf::StringPiece data) const {
  if (mac.size() != tag_size_) {
    return util::Status(util::error::INVALID_ARGUMENT, "incorrect tag size");
  }
  uint8_t buf[EVP_MAX_MD_SIZE];
  unsigned int out_len;
  const uint8_t* res = HMAC(md_, key_value_.data(), key_value_.size(),
                            reinterpret_cast<const uint8_t*>(data.data()),
                            data.size(), buf, &out_len);
  if (res == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "BoringSSL failed to compute HMAC");
  }
  uint8_t diff = 0;
  for (uint32_t i = 0; i < tag_size_; i++) {
    diff |= buf[i] ^ static_cast<uint8_t>(mac[i]);
  }
  if (diff == 0) {
    return util::Status::OK;
  } else {
    return util::Status(util::error::INVALID_ARGUMENT, "verification failed");
  }
}

}  // namespace tink
}  // namespace crypto
