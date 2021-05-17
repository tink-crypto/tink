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

#ifndef TINK_JWT_RAW_JWT_H_
#define TINK_JWT_RAW_JWT_H_

#include "google/protobuf/struct.pb.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// A raw JSON Web Token</a> (JWT), https://tools.ietf.org/html/rfc7519.
//
// It can be signed or MAC'ed to obtain a compact JWT. It can also be a token
// that has been parsed from a compact JWT, but not yet verified.
class RawJwt {
 public:
  RawJwt();

  bool HasTypeHeader() const;
  util::StatusOr<std::string> GetTypeHeader() const;
  bool HasIssuer() const;
  util::StatusOr<std::string> GetIssuer() const;
  bool HasSubject() const;
  util::StatusOr<std::string> GetSubject() const;
  bool HasAudiences() const;
  util::StatusOr<std::vector<std::string>> GetAudiences() const;
  bool HasJwtId() const;
  util::StatusOr<std::string> GetJwtId() const;
  bool HasExpiration() const;
  util::StatusOr<absl::Time> GetExpiration() const;
  bool HasNotBefore() const;
  util::StatusOr<absl::Time> GetNotBefore() const;
  bool HasIssuedAt() const;
  util::StatusOr<absl::Time> GetIssuedAt() const;
  bool IsNullClaim(absl::string_view name) const;
  bool HasBooleanClaim(absl::string_view name) const;
  util::StatusOr<bool> GetBooleanClaim(absl::string_view name) const;
  bool HasStringClaim(absl::string_view name) const;
  util::StatusOr<std::string> GetStringClaim(absl::string_view name) const;
  bool HasNumberClaim(absl::string_view name) const;
  util::StatusOr<double> GetNumberClaim(absl::string_view name) const;
  bool HasJsonObjectClaim(absl::string_view name) const;
  util::StatusOr<std::string> GetJsonObjectClaim(absl::string_view name) const;
  bool HasJsonArrayClaim(absl::string_view name) const;
  util::StatusOr<std::string> GetJsonArrayClaim(absl::string_view name) const;
  std::vector<std::string> CustomClaimNames() const;

  static util::StatusOr<RawJwt> FromJson(
      absl::optional<std::string> type_header, absl::string_view json_payload);
  util::StatusOr<std::string> GetJsonPayload() const;

  // RawJwt objects are copiable and movable.
  RawJwt(const RawJwt&) = default;
  RawJwt& operator=(const RawJwt&) = default;
  RawJwt(RawJwt&& other) = default;
  RawJwt& operator=(RawJwt&& other) = default;

 private:
  explicit RawJwt(absl::optional<std::string> type_header,
                  google::protobuf::Struct json_proto);
  friend class RawJwtBuilder;
  absl::optional<std::string> type_header_;
  google::protobuf::Struct json_proto_;
};

class RawJwtBuilder {
 public:
  RawJwtBuilder();

  RawJwtBuilder& SetTypeHeader(absl::string_view type_header);
  RawJwtBuilder& SetIssuer(absl::string_view issuer);
  RawJwtBuilder& SetSubject(absl::string_view subject);
  RawJwtBuilder& AddAudience(absl::string_view audience);
  RawJwtBuilder& SetJwtId(absl::string_view jwid);
  util::Status SetExpiration(absl::Time expiration);
  util::Status SetNotBefore(absl::Time notBefore);
  util::Status SetIssuedAt(absl::Time issuedAt);
  util::Status AddNullClaim(absl::string_view name);
  util::Status AddBooleanClaim(absl::string_view name, bool bool_value);
  util::Status AddStringClaim(absl::string_view name, std::string string_value);
  util::Status AddNumberClaim(absl::string_view name, double double_value);
  util::Status AddJsonObjectClaim(
      absl::string_view name, absl::string_view object_value);
  util::Status AddJsonArrayClaim(absl::string_view name,
                                 absl::string_view array_value);

  util::StatusOr<RawJwt> Build();

  // RawJwtBuilder objects are copiable and movable.
  RawJwtBuilder(const RawJwtBuilder&) = default;
  RawJwtBuilder& operator=(const RawJwtBuilder&) = default;
  RawJwtBuilder(RawJwtBuilder&& other) = default;
  RawJwtBuilder& operator=(RawJwtBuilder&& other) = default;

 private:
  absl::optional<std::string> type_header_;
  google::protobuf::Struct json_proto_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_RAW_JWT_H_
