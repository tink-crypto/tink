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

#include <string>

#include "google/protobuf/struct.pb.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

namespace jwt_internal {

// For friend declaration
class RawJwtParser;

}  // namespace jwt_internal

///////////////////////////////////////////////////////////////////////////////
// An unsigned JSON Web Token (JWT), https://tools.ietf.org/html/rfc7519.
//
// It contains all payload claims and a subset of the headers. It does not
// contain any headers that depend on the key, such as "alg" or "kid", because
// these headers are chosen when the token is signed and encoded, and should not
// be chosen by the user. This ensures that the key can be changed without any
// changes to the user code.
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

  util::StatusOr<std::string> GetJsonPayload() const;

  // RawJwt objects are copiable and movable.
  RawJwt(const RawJwt&) = default;
  RawJwt& operator=(const RawJwt&) = default;
  RawJwt(RawJwt&& other) = default;
  RawJwt& operator=(RawJwt&& other) = default;

 private:
  static util::StatusOr<RawJwt> FromJson(
      absl::optional<std::string> type_header, absl::string_view json_payload);
  explicit RawJwt(absl::optional<std::string> type_header,
                  google::protobuf::Struct json_proto);
  friend class RawJwtBuilder;
  friend class jwt_internal::RawJwtParser;
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
  RawJwtBuilder& WithoutExpiration();
  RawJwtBuilder& SetExpiration(absl::Time expiration);
  RawJwtBuilder& SetNotBefore(absl::Time not_before);
  RawJwtBuilder& SetIssuedAt(absl::Time issued_at);
  RawJwtBuilder& AddNullClaim(absl::string_view name);
  RawJwtBuilder& AddBooleanClaim(absl::string_view name, bool bool_value);
  RawJwtBuilder& AddStringClaim(absl::string_view name,
                                absl::string_view string_value);
  RawJwtBuilder& AddNumberClaim(absl::string_view name, double double_value);
  RawJwtBuilder& AddJsonObjectClaim(absl::string_view name,
                                    absl::string_view object_value);
  RawJwtBuilder& AddJsonArrayClaim(absl::string_view name,
                                   absl::string_view array_value);

  util::StatusOr<RawJwt> Build();

  // RawJwtBuilder objects are copiable and movable.
  RawJwtBuilder(const RawJwtBuilder&) = default;
  RawJwtBuilder& operator=(const RawJwtBuilder&) = default;
  RawJwtBuilder(RawJwtBuilder&& other) = default;
  RawJwtBuilder& operator=(RawJwtBuilder&& other) = default;

 private:
  absl::optional<util::Status> error_;
  absl::optional<std::string> type_header_;
  // absl::optional<absl::Time> expiration_;
  // absl::optional<absl::Time> not_before_;
  // absl::optional<absl::Time> issued_at_;
  bool without_expiration_;
  google::protobuf::Struct json_proto_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_RAW_JWT_H_
