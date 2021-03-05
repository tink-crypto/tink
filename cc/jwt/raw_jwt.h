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
#include "tink/jwt/jwt_names.h"
#include "tink/util/status.h"

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

  static util::StatusOr<RawJwt> FromString(absl::string_view json_string);
  util::StatusOr<std::string> ToString();

  // RawJwt objects are copiable and movable.
  RawJwt(const RawJwt&) = default;
  RawJwt& operator=(const RawJwt&) = default;
  RawJwt(RawJwt&& other) = default;
  RawJwt& operator=(RawJwt&& other) = default;

 private:
  explicit RawJwt(google::protobuf::Struct json_proto);
  friend class RawJwtBuilder;
  google::protobuf::Struct json_proto_;
};

class RawJwtBuilder {
 public:
  RawJwtBuilder();

  RawJwtBuilder& SetIssuer(absl::string_view issuer);
  RawJwtBuilder& SetSubject(absl::string_view subject);
  RawJwtBuilder& AddAudience(absl::string_view audience);
  RawJwtBuilder& SetJwtId(absl::string_view jwid);
  RawJwtBuilder& SetExpiration(absl::Time expiration);
  RawJwtBuilder& SetNotBefore(absl::Time notBefore);
  RawJwtBuilder& SetIssuedAt(absl::Time issuedAt);

  util::StatusOr<RawJwt> Build();

  // RawJwtBuilder objects are copiable and movable.
  RawJwtBuilder(const RawJwtBuilder&) = default;
  RawJwtBuilder& operator=(const RawJwtBuilder&) = default;
  RawJwtBuilder(RawJwtBuilder&& other) = default;
  RawJwtBuilder& operator=(RawJwtBuilder&& other) = default;

 private:
  google::protobuf::Struct json_proto_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_RAW_JWT_H_
