// Copyright 2019 Google LLC
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
#include "tink/kms_clients.h"

#include <vector>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "tink/kms_client.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

// static
KmsClients& KmsClients::GlobalInstance() {
  static KmsClients* instance = new KmsClients();
  return *instance;
}

Status KmsClients::LocalAdd(std::unique_ptr<KmsClient> kms_client) {
  if (kms_client == nullptr) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "kms_client must be non-null.");
  }
  absl::MutexLock lock(&clients_mutex_);
  clients_.push_back(std::move(kms_client));
  return util::OkStatus();
}

StatusOr<const KmsClient*> KmsClients::LocalGet(absl::string_view key_uri) {
  if (key_uri.empty()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "key_uri must be non-empty.");
  }
  absl::MutexLock lock(&clients_mutex_);
  for (const auto& client : clients_) {
    if (client->DoesSupport(key_uri)) return client.get();
  }
  return ToStatusF(absl::StatusCode::kNotFound,
                   "no KmsClient found for key '%s'.",
                   std::string(key_uri).c_str());
}

}  // namespace tink
}  // namespace crypto
