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
#ifndef TINK_EXAMPLES_WALKTHROUGH_TEST_UTIL_H_
#define TINK_EXAMPLES_WALKTHROUGH_TEST_UTIL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/kms_client.h"
#include "tink/util/statusor.h"

namespace tink_walkthrough {

// A fake KmsClient that for every key URI always returns an aead from
// kSerializedMasterKeyKeyset.
class FakeKmsClient : public crypto::tink::KmsClient {
 public:
  explicit FakeKmsClient(absl::string_view serialized_master_key_keyset)
      : serialized_master_key_keyset_(serialized_master_key_keyset) {}

  bool DoesSupport(absl::string_view key_uri) const override;

  crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::Aead>> GetAead(
      absl::string_view key_uri) const override;

 private:
  std::string serialized_master_key_keyset_;
};

// A fake KmsClient that always fails to return an AEAD.
class AlwaysFailingFakeKmsClient : public crypto::tink::KmsClient {
 public:
  bool DoesSupport(absl::string_view key_uri) const override;

  crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::Aead>> GetAead(
      absl::string_view key_uri) const override;
};

}  // namespace tink_walkthrough

#endif  // TINK_EXAMPLES_WALKTHROUGH_TEST_UTIL_H_
