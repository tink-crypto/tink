// Copyright 2018 Google LLC
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

#include "tink/internal/key_type_info_store.h"

#include <memory>
#include <typeindex>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

util::StatusOr<KeyTypeInfoStore::Info*> KeyTypeInfoStore::Get(
    absl::string_view type_url) const {
  auto it = type_url_to_info_.find(type_url);
  if (it == type_url_to_info_.end()) {
    return ToStatusF(absl::StatusCode::kNotFound,
                     "No manager for type '%s' has been registered.", type_url);
  }
  return it->second.get();
}

util::Status KeyTypeInfoStore::IsInsertable(
    absl::string_view type_url, const std::type_index& key_manager_type_index,
    bool new_key_allowed) const {
  auto it = type_url_to_info_.find(type_url);
  if (it == type_url_to_info_.end()) {
    return crypto::tink::util::OkStatus();
  }
  if (it->second->key_manager_type_index() != key_manager_type_index) {
    return ToStatusF(absl::StatusCode::kAlreadyExists,
                     "A manager for type '%s' has been already registered.",
                     type_url);
  }
  if (!it->second->new_key_allowed() && new_key_allowed) {
    return ToStatusF(absl::StatusCode::kAlreadyExists,
                     "A manager for type '%s' has been already registered "
                     "with forbidden new key operation.",
                     type_url);
  }
  return util::OkStatus();
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
