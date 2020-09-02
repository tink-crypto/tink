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

#ifndef TINK_JWT_JWT_H_
#define TINK_JWT_JWT_H_

#include "google/protobuf/struct.pb.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

class JwtTest;

///////////////////////////////////////////////////////////////////////////////
// Interface for a read-only implementation of
// https://tools.ietf.org/html/rfc7519 (json Web Token - JWT).
// A new instance of this class is returned as the result of
// a sucessfully verification of a JWT.
class Jwt {
 public:
  // Header Getters.
  util::StatusOr<std::string> GetType() const;
  util::StatusOr<std::string> GetContentType() const;
  util::StatusOr<std::string> GetAlgorithm() const;
  // Its value MUST be a case-sensitive string.
  // https://tools.ietf.org/html/rfc7515#section-4.1.4
  util::StatusOr<std::string> GetKeyId() const;

  // Payload Getters.
  // The "iss" value is a case-sensitive string.
  // https://tools.ietf.org/html/rfc7519#section-4.1.1
  util::StatusOr<std::string> GetIssuer() const;
  // The "sub" value is a case-sensitive string.
  // https://tools.ietf.org/html/rfc7519#section-4.1.2
  util::StatusOr<std::string> GetSubject() const;
  // The "jti" value is a case-sensitive string.
  // https://tools.ietf.org/html/rfc7519#section-4.1.7
  util::StatusOr<std::string> GetJwtId() const;
  // Its value MUST be a number containing a NumericDate value.
  // https://tools.ietf.org/html/rfc7519#section-4.1.4
  util::StatusOr<absl::Time> GetExpiration() const;
  // Its value MUST be a number containing a NumericDate value.
  // https://tools.ietf.org/html/rfc7519#section-4.1.5
  util::StatusOr<absl::Time> GetNotBefore() const;
  // Its value MUST be a number containing a NumericDate value.
  // https://tools.ietf.org/html/rfc7519#section-4.1.6
  util::StatusOr<absl::Time> GetIssuedAt() const;
  // the "aud" value is an array of case-sensitive strings, each containing a
  // StringOrURI value.  In the special case when the JWT has one audience, the
  // "aud" value MAY be a single case-sensitive string.
  // https://tools.ietf.org/html/rfc7519#section-4.1.3
  util::StatusOr<std::vector<std::string>> GetAudiences() const;
  util::StatusOr<std::string> GetClaimAsString(absl::string_view name) const;
  util::StatusOr<double> GetClaimAsNumber(absl::string_view name) const;
  util::StatusOr<bool> GetClaimAsBool(absl::string_view name) const;
  util::StatusOr<std::vector<std::string>> GetClaimAsStringList(
      absl::string_view name) const;
  util::StatusOr<std::vector<double>> GetClaimAsNumberList(
      absl::string_view name) const;

 private:
  friend class JwtTest;
  static util::StatusOr<std::unique_ptr<Jwt>> New(
      const google::protobuf::Struct& header,
      const google::protobuf::Struct& payload, const absl::Time clock,
      const absl::Duration clockSkew);
  util::Status validateTimestampClaims() const;

  Jwt(const google::protobuf::Struct& header,
      const google::protobuf::Struct& payload, const absl::Time clock,
      const absl::Duration clockSkew);
  util::StatusOr<std::string> GetValueAsString(
      const google::protobuf::Struct& j_proto, absl::string_view name) const;
  util::StatusOr<absl::Time> GetValueAsTime(
      const google::protobuf::Struct& j_proto, absl::string_view name) const;
  util::StatusOr<const google::protobuf::ListValue*> GetValueAsList(
      const google::protobuf::Struct& j_proto, absl::string_view name) const;
  util::StatusOr<bool> GetValueAsBool(const google::protobuf::Struct& j_proto,
                                      absl::string_view name) const;
  util::StatusOr<double> GetValueAsNumber(
      const google::protobuf::Struct& j_proto, absl::string_view name) const;
  google::protobuf::Struct header_;
  google::protobuf::Struct payload_;
  absl::Time clock_;
  absl::Duration clock_skew_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_H_
