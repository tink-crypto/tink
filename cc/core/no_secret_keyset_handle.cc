// Copyright 2017 Google Inc.
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

#include "tink/no_secret_keyset_handle.h"

#include "absl/memory/memory.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;

namespace crypto {
namespace tink {

namespace {

crypto::tink::util::Status Validate(const Keyset& keyset) {
  for (const google::crypto::tink::Keyset::Key& key : keyset.key()) {
    if (key.key_data().key_material_type() == KeyData::UNKNOWN_KEYMATERIAL ||
        key.key_data().key_material_type() == KeyData::SYMMETRIC ||
        key.key_data().key_material_type() == KeyData::ASYMMETRIC_PRIVATE) {
      return crypto::tink::util::Status(
          util::error::FAILED_PRECONDITION,
          "Cannot create KeysetHandle with secret key material from "
          "potentially unencrypted source.");
    }
  }
  return util::Status::OK;
}

}  // namespace

// static
util::StatusOr<std::unique_ptr<KeysetHandle>> NoSecretKeysetHandle::Get(
    google::crypto::tink::Keyset keyset) {
  util::Status validation = Validate(keyset);
  if (!validation.ok()) return validation;
  return absl::WrapUnique(new KeysetHandle(std::move(keyset)));
}

}  // namespace tink
}  // namespace crypto
