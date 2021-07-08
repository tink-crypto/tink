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

// A command-line utility for generating JSON Web Token (JWT) keys, and creating
// and verifying JWTs.
//
// The first argument is the operation and it should be one of the following:
// gen-private-key get-public-key sign verify.
// Additional arguments depend on the operation.
//
// gen-private-key
//   Generates a new private keyset using JwtRs256_2048_F4_Template.
//   It requires 1 additional argument:
//     output-file: name of the file for the resulting output
//
// get-public-key
//   Extracts a public keyset associated with the given private keyset.
//   It requires 2 additional arguments:
//     private-keyset-file: name of the file with the private keyset
//     output-file: name of the file for the resulting output
//
// sign
//   Generates and signs a token using the given private keyset.
//   It requires 3 additional arguments:
//     private-keyset-file: name of the file with the private keyset
//     subject: subject claim to be put in the token.
//     output-file: name of the file for the resulting output
//
// verify
//   Verifies a token using the given public keyset.
//   It requires 4 additional arguments:
//     public-keyset-file: name of the file with the public keyset
//     subject: expected subject in the token
//     token-file: name of the file with the token
//     output-file: name of the file for the resulting output (valid/invalid)

#include <iostream>
#include <string>

#include "tink/jwt/jwt_key_templates.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_signature_config.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "jwt/util.h"

// Prints usage info.
using crypto::tink::JwtPublicKeySign;
using crypto::tink::JwtPublicKeyVerify;
using crypto::tink::JwtValidator;
using crypto::tink::KeysetHandle;
using crypto::tink::RawJwt;
using crypto::tink::RawJwtBuilder;

void PrintUsageInfo() {
  std::clog << "Usage: operation arguments\n"
            << "where operation is one of the following:\n"
            << "  gen-private-key get-public-key sign verify\n"
            << "and, depending on the operation, arguments are:\n"
            << "  gen-private-key: output-file\n"
            << "  get-public-key: private-keyset-file output-file\n"
            << "  sign: private-keyset-file subject output-file\n"
            << "  verify: public-keyset-file subject token-file "
            << "output-file" << std::endl;
}

// Generates a new private keyset using JwtRs256_2048_F4_Template and writes it
// to the output file.
void GeneratePrivateKey(absl::string_view output_filename) {
  std::clog << "Generating a new private keyset.." << std::endl;

  auto key_template = crypto::tink::JwtRs256_2048_F4_Template();
  crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      crypto::tink::KeysetHandle::GenerateNew(key_template);
  if (!keyset_handle.ok()) {
    std::clog << "Generating new keyset failed: "
              << keyset_handle.status().error_message() << std::endl;
    exit(1);
  }
  std::clog << "Writing the keyset to file " << output_filename
            << "..." << std::endl;

  WriteKeyset(**keyset_handle, output_filename);
}

// Extracts a public keyset associated with the given private keyset
// and writes it to the output file.
void ExtractPublicKey(absl::string_view private_keyset_filename,
                      absl::string_view output_filename) {
  std::clog << "Extracting a public keyset associated with the private "
            << "keyset from file " << private_keyset_filename << "..."
            << std::endl;

  std::unique_ptr<crypto::tink::KeysetHandle> private_keyset_handle =
      ReadKeyset(private_keyset_filename);

  crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>>
      public_keyset_handle = private_keyset_handle->GetPublicKeysetHandle();
  if (!public_keyset_handle.ok()) {
    std::clog << "Getting the keyset failed: "
              << public_keyset_handle.status().error_message() << std::endl;
    exit(1);
  }

  std::clog << "Writing the keyset to file " << output_filename
            << "..." << std::endl;

  WriteKeyset(**public_keyset_handle, output_filename);
}

// Creates and signs a token with the given subject claim using the given
// private keyset and writes the signature to the output file.
void Sign(absl::string_view keyset_filename, absl::string_view subject,
          absl::string_view output_filename) {
  std::unique_ptr<crypto::tink::KeysetHandle> keyset_handle =
      ReadKeyset(keyset_filename);

  crypto::tink::util::StatusOr<std::unique_ptr<JwtPublicKeySign>>
      jwt_public_key_sign = keyset_handle->GetPrimitive<JwtPublicKeySign>();
  if (!jwt_public_key_sign.ok()) {
    std::clog << "Getting JwtPublicKeySign-primitive from the factory failed: "
              << jwt_public_key_sign.status().error_message() << std::endl;
    exit(1);
  }

  std::clog << "Generating a token with subject '" << subject
            << "' using private keyset from file " << keyset_filename << "..."
            << std::endl;

  crypto::tink::util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder()
          .SetSubject(subject)
          .SetExpiration(absl::Now() + absl::Seconds(100))
          .Build();
  if (!raw_jwt.ok()) {
    std::clog << "Building RawJwt failed: " << raw_jwt.status().error_message()
              << std::endl;
    exit(1);
  }

  crypto::tink::util::StatusOr<std::string> token =
      (*jwt_public_key_sign)->SignAndEncode(*raw_jwt);
  if (!token.ok()) {
    std::clog << "Error while generating the token: "
              << token.status().error_message() << std::endl;
    exit(1);
  }

  std::clog << "Writing the resulting token to file " << output_filename
            << "..." << std::endl;

  WriteFile(*token, output_filename);
}

// Verifies a token using the given public keyset and writes the result to the
// output file.
void Verify(absl::string_view keyset_filename,
            absl::string_view expected_subject,
            absl::string_view token_filename,
            absl::string_view output_filename) {
  std::unique_ptr<KeysetHandle> keyset_handle = ReadKeyset(keyset_filename);

  crypto::tink::util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verifier =
      keyset_handle->GetPrimitive<crypto::tink::JwtPublicKeyVerify>();
  if (!verifier.ok()) {
    std::clog << "Getting JwtPublicKeyVerify-primitive from the factory "
              << "failed: " << verifier.status().error_message() << std::endl;
    exit(1);
  }

  std::clog << "Verifying token from file " << token_filename
            << " with expected subject '" << expected_subject
            << "' using public keyset from file " << keyset_filename << "..."
            << std::endl;

  std::string token = ReadFile(token_filename);

  crypto::tink::util::StatusOr<JwtValidator> validator =
      crypto::tink::JwtValidatorBuilder()
          .ExpectSubject(expected_subject)
          .Build();
  if (!validator.ok()) {
    std::clog << "Building validator failed: "
              << validator.status().error_message() << std::endl;
    exit(1);
  }

  std::string result;
  crypto::tink::util::StatusOr<crypto::tink::VerifiedJwt> verified_jwt =
      (*verifier)->VerifyAndDecode(token, *validator);
  if (!verified_jwt.ok()) {
    std::clog << "Error while verifying the token: "
              << verified_jwt.status().error_message() << std::endl;
    result = "invalid";
  } else {
    absl::Duration ttl = *verified_jwt->GetExpiration() - absl::Now();
    std::clog << "Token is valid for " << ttl << "." << std::endl;
    result = "valid";
  }

  std::clog << "Writing the result to file " << output_filename
            << "..." << std::endl;

  WriteFile(result, output_filename);
}

int main(int argc, char** argv) {
  if (argc == 1) {
    PrintUsageInfo();
    exit(1);
  }

  crypto::tink::util::Status status = crypto::tink::JwtSignatureRegister();
  if (!status.ok()) {
    std::clog << "JwtSignatureRegister() failed: " << status.error_message()
              << std::endl;
    exit(1);
  }

  std::string operation = argv[1];

  if (operation == "gen-private-key") {
    if (argc != 3) {
      PrintUsageInfo();
      exit(1);
    }

    std::string output_filename = argv[2];

    GeneratePrivateKey(output_filename);
  } else if (operation == "get-public-key") {
    if (argc != 4) {
      PrintUsageInfo();
      exit(1);
    }

    std::string private_keyset_filename = argv[2];
    std::string output_filename = argv[3];

    ExtractPublicKey(private_keyset_filename, output_filename);
  } else if (operation == "sign") {
    if (argc != 5) {
      PrintUsageInfo();
      exit(1);
    }

    std::string keyset_filename = argv[2];
    std::string subject = argv[3];
    std::string output_filename = argv[4];

    Sign(keyset_filename, subject, output_filename);
  } else if (operation == "verify") {
    if (argc != 6) {
      PrintUsageInfo();
      exit(1);
    }

    std::string keyset_filename = argv[2];
    std::string subject = argv[3];
    std::string token_filename = argv[4];
    std::string output_filename = argv[5];

    Verify(keyset_filename, subject, token_filename, output_filename);
  } else {
    std::clog << "Unknown operation. Supported operations are: "
              << "gen-private-key get-public-key sign verify" << std::endl;
    exit(1);
  }

  std::clog << "Done!" << std::endl;

  return 0;
}
