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

#include "cc/subtle/hmac_openssl.h"

#include "cc/mac.h"
#include "cc/util/errors.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "proto/common.pb.h"

using google::cloud::crypto::tink::HashType;

namespace cloud {
namespace crypto {
namespace tink {

// static
util::StatusOr<std::unique_ptr<Mac>> HmacOpenSsl::New(
    HashType hash_type, int tag_size, const std::string& key_value) {
  std::unique_ptr<Mac> hmac(
      new HmacOpenSsl(hash_type, tag_size, key_value));
  return std::move(hmac);
}

HmacOpenSsl::HmacOpenSsl(
    HashType hash_type, int tag_size, const std::string& key_value)
    : hash_type_(hash_type), tag_size_(tag_size), key_value_(key_value) {
}

util::StatusOr<std::string> HmacOpenSsl::ComputeMac(
    google::protobuf::StringPiece data) const {
  return util::Status::UNKNOWN;
}

util::Status HmacOpenSsl::VerifyMac(
    google::protobuf::StringPiece mac,
    google::protobuf::StringPiece data) const {
  return util::Status::UNKNOWN;
}

}  // namespace tink
}  // namespace crypto
}  // namespace cloud
