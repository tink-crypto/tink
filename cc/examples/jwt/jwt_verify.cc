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
// [START jwt-verify]
// A utility for creating, signing and verifying JSON Web Tokens (JWT).
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "util/util.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_signature_config.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"

ABSL_FLAG(std::string, keyset_filename, "", "Keyset file in JSON format");
ABSL_FLAG(std::string, audience, "", "Expected audience in the token");
ABSL_FLAG(std::string, token_filename, "", "Path to the token file");

namespace {

using ::crypto::tink::JwtPublicKeyVerify;
using ::crypto::tink::JwtValidator;
using ::crypto::tink::KeysetHandle;
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

// JWT verify example CLI implementation.
Status JwtVerify(const std::string& keyset_filename, absl::string_view audience,
                 const std::string& token_filename) {
  Status result = crypto::tink::JwtSignatureRegister();
  if (!result.ok()) return result;

  // Read the keyset from file.
  StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      ReadJsonCleartextKeyset(keyset_filename);
  if (!keyset_handle.ok()) return keyset_handle.status();

  // Read the token.
  StatusOr<std::string> token = ReadFile(token_filename);
  if (!token.ok()) return token.status();

  StatusOr<JwtValidator> validator =
      crypto::tink::JwtValidatorBuilder().ExpectAudience(audience).Build();
  if (!validator.ok()) return validator.status();

  StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verifier =
      (*keyset_handle)->GetPrimitive<JwtPublicKeyVerify>();
  if (!jwt_verifier.ok()) return jwt_verifier.status();

  return (*jwt_verifier)->VerifyAndDecode(*token, *validator).status();
}

}  // namespace tink_cc_examples

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  ValidateParams();

  std::string keyset_filename = absl::GetFlag(FLAGS_keyset_filename);
  std::string audience = absl::GetFlag(FLAGS_audience);
  std::string token_filename = absl::GetFlag(FLAGS_token_filename);

  std::clog << "Using keyset in " << keyset_filename << " to ";
  std::clog << " verify a token with expected audience '" << audience
            << std::endl;

  CHECK_OK(
      tink_cc_examples::JwtVerify(keyset_filename, audience, token_filename));
  return 0;
}
// [END jwt-verify]
