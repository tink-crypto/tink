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

#include "cc/hybrid/hybrid_decrypt_factory.h"

#include "cc/hybrid_decrypt.h"
#include "cc/key_manager.h"
#include "cc/keyset_handle.h"
#include "cc/registry.h"
#include "cc/hybrid/hybrid_decrypt_set_wrapper.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"

namespace util = crypto::tink::util;

namespace crypto {
namespace tink {

// static
util::StatusOr<std::unique_ptr<HybridDecrypt>>
HybridDecryptFactory::GetPrimitive(const KeysetHandle& keyset_handle) {
  return GetPrimitive(keyset_handle, nullptr);
}

// static
util::StatusOr<std::unique_ptr<HybridDecrypt>>
HybridDecryptFactory::GetPrimitive(const KeysetHandle& keyset_handle,
    const KeyManager<HybridDecrypt>* custom_key_manager) {
  auto primitives_result = Registry::GetPrimitives<HybridDecrypt>(
      keyset_handle, custom_key_manager);
  if (primitives_result.ok()) {
    return HybridDecryptSetWrapper::NewHybridDecrypt(
        std::move(primitives_result.ValueOrDie()));
  }
  return primitives_result.status();
}

}  // namespace tink
}  // namespace crypto
