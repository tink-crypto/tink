// Copyright 2018 Google Inc.
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

#include "tink/util/test_keyset_handle.h"

#include <utility>

#include "absl/memory/memory.h"
#include "tink/keyset_handle.h"
#include "proto/tink.pb.h"

using google::crypto::tink::Keyset;

namespace crypto {
namespace tink {

// static
std::unique_ptr<KeysetHandle> TestKeysetHandle::GetKeysetHandle(
    const Keyset& keyset) {
  auto unique_keyset = absl::make_unique<Keyset>(keyset);
  std::unique_ptr<KeysetHandle> handle =
      absl::WrapUnique(new KeysetHandle(std::move(unique_keyset)));
  return handle;
}

// static
const Keyset& TestKeysetHandle::GetKeyset(const KeysetHandle& keyset_handle) {
  return keyset_handle.get_keyset();
}

}  // namespace tink
}  // namespace crypto
