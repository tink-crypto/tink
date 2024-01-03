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
// [START key-derivation-example]
// A command-line utility for testing Tink Key Derivation.
#include <iostream>
#include <memory>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "util/util.h"
#include "tink/keyderivation/key_derivation_config.h"
#include "tink/keyderivation/keyset_deriver.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"

ABSL_FLAG(std::string, keyset_filename, "",
          "File in JSON format containing keyset that derives an AEAD keyset");
ABSL_FLAG(std::string, salt_filename, "", "Salt file name");
ABSL_FLAG(std::string, derived_keyset_filename, "", "Derived keyset file name");

namespace {

using ::crypto::tink::Aead;
using ::crypto::tink::AeadConfig;
using ::crypto::tink::KeyDerivationConfig;
using ::crypto::tink::KeysetDeriver;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::util::OkStatus;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;

void ValidateParams() {
  // [START_EXCLUDE]
  CHECK(!absl::GetFlag(FLAGS_keyset_filename).empty())
      << "Keyset file must be specified";
  CHECK(!absl::GetFlag(FLAGS_salt_filename).empty())
      << "Input file must be specified";
  CHECK(!absl::GetFlag(FLAGS_derived_keyset_filename).empty())
      << "Output file must be specified";
  // [END_EXCLUDE]
}

// Verifies `handle` contains a valid AEAD primitive.
Status VerifyDerivedAeadKeyset(const KeysetHandle& handle) {
  // [START_EXCLUDE]
  StatusOr<std::unique_ptr<Aead>> aead =
      handle.GetPrimitive<crypto::tink::Aead>(
          crypto::tink::ConfigGlobalRegistry());
  if (!aead.ok()) return aead.status();

  std::string plaintext = "plaintext";
  std::string ad = "ad";
  StatusOr<std::string> ciphertext = (*aead)->Encrypt(plaintext, ad);
  if (!ciphertext.ok()) return ciphertext.status();

  StatusOr<std::string> got = (*aead)->Decrypt(*ciphertext, ad);
  if (!got.ok()) return got.status();

  if (*got != plaintext) {
    return Status(
        absl::StatusCode::kInternal,
        "AEAD obtained from derived keyset failed to decrypt correctly");
  }
  return OkStatus();
  // [END_EXCLUDE]
}

}  // namespace

namespace tink_cc_examples {

Status KeyDerivationCli(const std::string& keyset_filename,
                        const std::string& salt_filename,
                        const std::string& derived_keyset_filename) {
  Status result = KeyDerivationConfig::Register();
  if (!result.ok()) return result;
  result = AeadConfig::Register();
  if (!result.ok()) return result;

  // Read keyset from file.
  StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      ReadJsonCleartextKeyset(keyset_filename);
  if (!keyset_handle.ok()) return keyset_handle.status();

  // Get the primitive.
  StatusOr<std::unique_ptr<KeysetDeriver>> deriver =
      (*keyset_handle)
          ->GetPrimitive<crypto::tink::KeysetDeriver>(
              crypto::tink::ConfigGlobalRegistry());
  if (!deriver.ok()) return deriver.status();

  // Read the salt.
  StatusOr<std::string> salt_file_content = ReadFile(salt_filename);
  if (!salt_file_content.ok()) return salt_file_content.status();

  // Derive new keyset.
  StatusOr<std::unique_ptr<KeysetHandle>> derived_handle =
      (*deriver)->DeriveKeyset(*salt_file_content);
  if (!derived_handle.ok()) return derived_handle.status();

  Status status = VerifyDerivedAeadKeyset(**derived_handle);
  if (!status.ok()) return status;

  return WriteJsonCleartextKeyset(derived_keyset_filename, **derived_handle);
}

}  // namespace tink_cc_examples

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  ValidateParams();

  std::string keyset_filename = absl::GetFlag(FLAGS_keyset_filename);
  std::string salt_filename = absl::GetFlag(FLAGS_salt_filename);
  std::string derived_keyset_filename =
      absl::GetFlag(FLAGS_derived_keyset_filename);

  std::clog << "Using keyset from file " << keyset_filename
            << " to derive a new AEAD keyset with the salt in file "
            << salt_filename << "." << '\n';
  std::clog << "The resulting derived keyset will be written to "
            << derived_keyset_filename << "." << '\n';

  CHECK_OK(tink_cc_examples::KeyDerivationCli(keyset_filename, salt_filename,
                                              derived_keyset_filename));
  return 0;
}
// [END key-derivation-example]
