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

#ifndef TINK_JWT_JWT_OBJECT_H_
#define TINK_JWT_JWT_OBJECT_H_

#include "google/protobuf/struct.pb.h"
#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "tink/jwt/json_field_types.h"
#include "tink/jwt/json_object.h"
#include "tink/jwt/jwt_names.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Utility getters and setters for a JWT object.
// This class encapsulates two Json objects: a header and a payload.
// This class is intended for internal use only.
// The getter functions:
// - return util::error::NOT_FOUND if the requested header
// or claim does not exist.
// - return util::error::INVALID_ARGUMENT if the type of
// the requested header or claim does not match.
class JwtObject {
 public:
  explicit JwtObject(const JsonObject& payload);
  JwtObject();

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
  util::StatusOr<int> GetClaimAsNumber(absl::string_view name) const;
  util::StatusOr<bool> GetClaimAsBool(absl::string_view name) const;
  util::StatusOr<std::vector<std::string>> GetClaimAsStringList(
      absl::string_view name) const;
  util::StatusOr<std::vector<int>> GetClaimAsNumberList(
      absl::string_view name) const;

  // Payload setters
  util::Status SetIssuer(absl::string_view issuer);
  // The "sub" value is a case-sensitive string.
  // https://tools.ietf.org/html/rfc7519#section-4.1.2
  util::Status SetSubject(absl::string_view subject);
  // The "jti" value is a case-sensitive string.
  // https://tools.ietf.org/html/rfc7519#section-4.1.7
  util::Status SetJwtId(absl::string_view jwid);
  // Its value MUST be a number containing a NumericDate value.
  // https://tools.ietf.org/html/rfc7519#section-4.1.4
  util::Status SetExpiration(absl::Time expiration);
  // Its value MUST be a number containing a NumericDate value.
  // https://tools.ietf.org/html/rfc7519#section-4.1.5
  util::Status SetNotBefore(absl::Time notBefore);
  // Its value MUST be a number containing a NumericDate value.
  // https://tools.ietf.org/html/rfc7519#section-4.1.6
  util::Status SetIssuedAt(absl::Time issuedAt);
  util::Status AddAudience(absl::string_view audience);
  util::Status SetClaimAsString(absl::string_view name,
                                absl::string_view value);
  util::Status SetClaimAsNumber(absl::string_view name, int value);
  util::Status SetClaimAsBool(absl::string_view name, bool value);
  util::Status AppendClaimToStringList(absl::string_view name,
                                       absl::string_view value);
  util::Status AppendClaimToNumberList(absl::string_view name, int value);

  // List of field names and their type.
  util::StatusOr<absl::flat_hash_map<std::string, enum JsonFieldType>>
  getClaimNamesAndTypes();

 private:
  util::StatusOr<absl::string_view> AlgorithmTypeToString(
      const enum JwtAlgorithm algorithm) const;
  util::StatusOr<enum JwtAlgorithm> AlgorithmStringToType(
      absl::string_view algo_name) const;
  util::Status ValidateHeaderName(absl::string_view name);
  util::Status ValidatePayloadName(absl::string_view name);
  bool IsRegisteredHeaderName(absl::string_view name);
  bool IsRegisteredPayloadName(absl::string_view name);

 private:
  JsonObject payload_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_OBJECT_H_
