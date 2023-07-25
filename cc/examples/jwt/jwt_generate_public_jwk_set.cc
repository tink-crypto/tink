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
// [START jwt-generate-public-jwk-set]
// An example for converting a Tink keyset with public keys into a JWK set.
#include <iostream>
#include <memory>
#include <ostream>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "util/util.h"
#include "tink/jwt/jwk_set_converter.h"
#include "tink/jwt/jwt_signature_config.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"

ABSL_FLAG(std::string, public_keyset_filename, "",
          "Public keyset file in Tink's JSON format");
ABSL_FLAG(std::string, public_jwk_set_filename, "",
          "Path to the output public JWK set file");

namespace {

using ::crypto::tink::JwkSetFromPublicKeysetHandle;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;

void ValidateParams() {
  // [START_EXCLUDE]
  CHECK(!absl::GetFlag(FLAGS_public_keyset_filename).empty())
      << "Public keyset file must be specified";
  CHECK(!absl::GetFlag(FLAGS_public_jwk_set_filename).empty())
      << "Public JWK set file must be specified";
  // [END_EXCLUDE]
}

}  // namespace

namespace tink_cc_examples {

Status JwtGeneratePublicJwkSet(const std::string& public_keyset_filename,
                               const std::string& public_jwk_set_filename) {
  Status result = crypto::tink::JwtSignatureRegister();
  if (!result.ok()) return result;

  StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      ReadJsonCleartextKeyset(public_keyset_filename);
  if (!keyset_handle.ok()) return keyset_handle.status();

  StatusOr<std::string> public_jwk_set =
      JwkSetFromPublicKeysetHandle(**keyset_handle);
  if (!public_jwk_set.ok()) return keyset_handle.status();

  return WriteToFile(*public_jwk_set, public_jwk_set_filename);
}

}  // namespace tink_cc_examples

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  ValidateParams();

  std::string public_keyset_filename =
      absl::GetFlag(FLAGS_public_keyset_filename);
  std::string public_jwk_set_filename =
      absl::GetFlag(FLAGS_public_jwk_set_filename);

  std::clog << "Convert public keyset in " << public_keyset_filename << " to ";
  std::clog << " to JWK set format; the result is written to "
            << public_jwk_set_filename << std::endl;

  CHECK_OK(tink_cc_examples::JwtGeneratePublicJwkSet(public_keyset_filename,
                                                     public_jwk_set_filename));
  return 0;
}
// [END jwt-generate-public-jwk-set]
