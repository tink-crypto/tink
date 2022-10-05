// Copyright 2022 Google LLC
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

#include "walkthrough/test_util.h"

#include <memory>

#include "absl/strings/match.h"
#include "walkthrough/load_cleartext_keyset.h"
#include "tink/keyset_handle.h"

namespace tink_walkthrough {

using ::crypto::tink::Aead;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;

bool FakeKmsClient::DoesSupport(absl::string_view key_uri) const {
  return absl::StartsWith(key_uri, "fake://");
}

StatusOr<std::unique_ptr<Aead>> FakeKmsClient::GetAead(
    absl::string_view key_uri) const {
  StatusOr<std::unique_ptr<KeysetHandle>> master_key_keyset =
      LoadKeyset(serialized_master_key_keyset_);
  if (!master_key_keyset.ok()) {
    return master_key_keyset.status();
  }
  return (*master_key_keyset)->GetPrimitive<Aead>();
}

bool AlwaysFailingFakeKmsClient::DoesSupport(absl::string_view key_uri) const {
  return absl::StartsWith(key_uri, "failing://");
}

StatusOr<std::unique_ptr<Aead>> AlwaysFailingFakeKmsClient::GetAead(
    absl::string_view key_uri) const {
  return Status(absl::StatusCode::kUnimplemented, "Unimplemented");
}

}  // namespace tink_walkthrough
