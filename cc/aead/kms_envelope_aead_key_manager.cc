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

#include "tink/aead/kms_envelope_aead_key_manager.h"

#include <memory>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/kms_envelope_aead.h"
#include "tink/kms_client.h"
#include "tink/kms_clients.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/kms_envelope.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::KmsEnvelopeAeadKey;

StatusOr<std::unique_ptr<Aead>> KmsEnvelopeAeadKeyManager::AeadFactory::Create(
    const KmsEnvelopeAeadKey& key) const {
  const auto& kek_uri = key.params().kek_uri();
  auto kms_client_result = KmsClients::Get(kek_uri);
  if (!kms_client_result.ok()) return kms_client_result.status();
  auto aead_result = kms_client_result.value()->GetAead(kek_uri);
  if (!aead_result.ok()) return aead_result.status();
  return KmsEnvelopeAead::New(key.params().dek_template(),
                              std::move(aead_result.value()));
}

}  // namespace tink
}  // namespace crypto
