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
// [START jwt-example]
// A utility for creating, signing and verifying JSON Web Tokens (JWT).
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "util/util.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_signature_config.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"

ABSL_FLAG(std::string, keyset_filename, "", "Keyset file in JSON format");
ABSL_FLAG(std::string, mode, "", "Mode of operation (sign|verify)");
ABSL_FLAG(std::string, audience, "", "Expected audience in the token");
ABSL_FLAG(std::string, token_filename, "", "Path to the token file");

namespace {

using ::crypto::tink::JwtPublicKeySign;
using ::crypto::tink::JwtPublicKeyVerify;
using ::crypto::tink::JwtValidator;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::RawJwt;
using ::crypto::tink::RawJwtBuilder;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;

constexpr absl::string_view kSign = "sign";
constexpr absl::string_view kVerify = "verify";

// [START_EXCLUDE]
void ValidateParams() {
  if (absl::GetFlag(FLAGS_mode).empty() ||
      (absl::GetFlag(FLAGS_mode) != kSign &&
       absl::GetFlag(FLAGS_mode) != kVerify)) {
    std::cerr << "ERROR: Invalid mode; must be `" << kSign << "` or `"
              << kVerify << "`" << std::endl;
    exit(1);
  }

  if (absl::GetFlag(FLAGS_keyset_filename).empty()) {
    std::cerr << "ERROR: Keyset file must be specified" << std::endl;
    exit(1);
  }

  if (absl::GetFlag(FLAGS_audience).empty()) {
    std::cerr << "ERROR: Expected audience in the token must be specified"
              << std::endl;
    exit(1);
  }

  if (absl::GetFlag(FLAGS_token_filename).empty()) {
    std::cerr << "ERROR: Token file must be specified" << std::endl;
    exit(1);
  }
}
// [END_EXCLUDE]
}  // namespace

namespace tink_cc_examples {

// JWT example CLI implementation.
Status JwtCli(absl::string_view mode, const std::string& keyset_filename,
              absl::string_view audience, const std::string& token_filename) {
  Status result = crypto::tink::JwtSignatureRegister();
  if (!result.ok()) return result;

  // Read the keyset from file.
  StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      ReadJsonCleartextKeyset(keyset_filename);
  if (!keyset_handle.ok()) return keyset_handle.status();

  if (mode == kSign) {
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
  } else {  // mode == kVerify
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
}
}  // namespace tink_cc_examples

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  ValidateParams();

  std::string mode = absl::GetFlag(FLAGS_mode);
  std::string keyset_filename = absl::GetFlag(FLAGS_keyset_filename);
  std::string audience = absl::GetFlag(FLAGS_audience);
  std::string token_filename = absl::GetFlag(FLAGS_token_filename);

  std::clog << "Using keyset in " << keyset_filename << " to ";
  if (mode == kSign) {
    std::clog << " generate and sign a token using audience '" << audience
              << "'; the resulting signature is written to " << token_filename
              << std::endl;
  } else {  // mode == kVerify
    std::clog << " verify a token with expected audience '" << audience
              << std::endl;
  }

  Status result =
      tink_cc_examples::JwtCli(mode, keyset_filename, audience, token_filename);
  if (!result.ok()) {
    std::cerr << result.message() << std::endl;
    exit(1);
  }

  return 0;
}
// [END jwt-example]
