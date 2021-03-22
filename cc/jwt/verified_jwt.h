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

#ifndef TINK_JWT_VERIFIED_JWT_H_
#define TINK_JWT_VERIFIED_JWT_H_

#include "google/protobuf/struct.pb.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/jwt/raw_jwt.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// A read-only JSON Web Token</a> (JWT), https://tools.ietf.org/html/rfc7519.
//
// A new instance of this class is returned as the result of a sucessfully
// verification of a JWT. It contains the payload of the token, but no header
// information (typ, cty, alg and kid).
class VerifiedJwt {
 public:
  // TODO(juerg): Restrict access to this constructor.
  // VerifiedJwt object should only be constructed by JWT primitives and maybe
  // the VerifedJwt Tests. I first have to figure out what's the best way to do
  // this.
  VerifiedJwt();
  explicit VerifiedJwt(RawJwt raw_jwt);

  // VerifiedJwt objects are copiable and movable.
  VerifiedJwt(const VerifiedJwt&) = default;
  VerifiedJwt& operator=(const VerifiedJwt&) = default;
  VerifiedJwt(VerifiedJwt&& other) = default;
  VerifiedJwt& operator=(VerifiedJwt&& other) = default;

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

  util::StatusOr<std::string> ToString();



 private:
  RawJwt raw_jwt_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_VERIFIED_JWT_H_
