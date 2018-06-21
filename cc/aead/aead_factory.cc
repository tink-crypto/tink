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

#include "tink/aead/aead_factory.h"

#include "tink/aead.h"
#include "tink/key_manager.h"
#include "tink/keyset_handle.h"
#include "tink/registry.h"
#include "tink/aead/aead_set_wrapper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"


namespace crypto {
namespace tink {

// static
util::StatusOr<std::unique_ptr<Aead>> AeadFactory::GetPrimitive(
    const KeysetHandle& keyset_handle) {
  return GetPrimitive(keyset_handle, nullptr);
}

// static
util::StatusOr<std::unique_ptr<Aead>> AeadFactory::GetPrimitive(
    const KeysetHandle& keyset_handle,
    const KeyManager<Aead>* custom_key_manager) {
  auto primitives_result = Registry::GetPrimitives<Aead>(
      keyset_handle, custom_key_manager);
  if (primitives_result.ok()) {
    return AeadSetWrapper::NewAead(std::move(primitives_result.ValueOrDie()));
  }
  return primitives_result.status();
}


}  // namespace tink
}  // namespace crypto
