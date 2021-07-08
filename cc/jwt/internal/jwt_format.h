// Copyright 2021 Google LLC
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

#ifndef TINK_JWT_INTERNAL_JWT_FORMAT_H_
#define TINK_JWT_INTERNAL_JWT_FORMAT_H_

#include <string>

#include "google/protobuf/struct.pb.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

std::string EncodeHeader(absl::string_view json_header);
bool DecodeHeader(absl::string_view header, std::string* json_header);

absl::optional<std::string> GetKid(
    uint32_t key_id,
    ::google::crypto::tink::OutputPrefixType output_prefix_type);
absl::optional<uint32_t> GetKeyId(absl::string_view kid);

util::StatusOr<std::string> CreateHeader(absl::string_view algorithm,
                         absl::optional<absl::string_view> type_header,
                         absl::optional<absl::string_view> kid);
util::Status ValidateHeader(const google::protobuf::Struct& header,
                            absl::string_view algorithm);
absl::optional<std::string> GetTypeHeader(
    const google::protobuf::Struct& header);

std::string EncodePayload(absl::string_view json_payload);
bool DecodePayload(absl::string_view payload, std::string* json_payload);

std::string EncodeSignature(absl::string_view signature);
bool DecodeSignature(absl::string_view encoded_signature,
                     std::string* signature);

class RawJwtParser {
 public:
  static util::StatusOr<RawJwt> FromJson(
      absl::optional<std::string> type_header, absl::string_view json_payload);
};

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_FORMAT_H_
