// Copyright 2023 Google LLC
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
// [START jwt-sign]
// An example for signing JSON Web Tokens (JWT).
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "util/util.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_signature_config.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"

ABSL_FLAG(std::string, keyset_filename, "", "Keyset file in JSON format");
ABSL_FLAG(std::string, audience, "", "Expected audience in the token");
ABSL_FLAG(std::string, token_filename, "", "Path to the token file");

namespace {

using ::crypto::tink::JwtPublicKeySign;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::RawJwt;
using ::crypto::tink::RawJwtBuilder;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;

void ValidateParams() {
  // [START_EXCLUDE]
  CHECK(!absl::GetFlag(FLAGS_keyset_filename).empty())
      << "Keyset file must be specified";
  CHECK(!absl::GetFlag(FLAGS_audience).empty())
      << "Expected audience in the token must be specified";
  CHECK(!absl::GetFlag(FLAGS_token_filename).empty())
      << "Token file must be specified";
  // [END_EXCLUDE]
}

}  // namespace

namespace tink_cc_examples {

// JWT sign example CLI implementation.
Status JwtSign(const std::string& keyset_filename, absl::string_view audience,
               const std::string& token_filename) {
  Status result = crypto::tink::JwtSignatureRegister();
  if (!result.ok()) return result;

  // Read the keyset from file.
  StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      ReadJsonCleartextKeyset(keyset_filename);
  if (!keyset_handle.ok()) return keyset_handle.status();
  StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder()
          .AddAudience(audience)
          .SetExpiration(absl::Now() + absl::Seconds(100))
          .Build();
  if (!raw_jwt.ok()) return raw_jwt.status();
  StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_signer =
      (*keyset_handle)->GetPrimitive<JwtPublicKeySign>();
  if (!jwt_signer.ok()) return jwt_signer.status();

  StatusOr<std::string> token = (*jwt_signer)->SignAndEncode(*raw_jwt);
  if (!token.ok()) return token.status();

  return WriteToFile(*token, token_filename);
}

}  // namespace tink_cc_examples

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  ValidateParams();

  std::string keyset_filename = absl::GetFlag(FLAGS_keyset_filename);
  std::string audience = absl::GetFlag(FLAGS_audience);
  std::string token_filename = absl::GetFlag(FLAGS_token_filename);

  std::clog << "Using keyset in " << keyset_filename << " to ";
  std::clog << " generate and sign a token using audience '" << audience
            << "'; the resulting signature is written to " << token_filename
            << std::endl;

  CHECK_OK(
      tink_cc_examples::JwtSign(keyset_filename, audience, token_filename));
  return 0;
}
// [END jwt-sign]
