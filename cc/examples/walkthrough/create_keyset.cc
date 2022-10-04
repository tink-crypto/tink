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

#include "walkthrough/create_keyset.h"

// [START tink_walkthrough_create_keyset]
#include <memory>

#include "tink/aead/aead_key_templates.h"
#include "tink/keyset_handle.h"

namespace tink_walkthrough {

using ::crypto::tink::KeysetHandle;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::KeyTemplate;

// Creates a keyset with a single AES256-GCM-SIV key and return a handle to
// it.
//
// Prerequisites for this example:
//  - Register AEAD implementations of Tink.
StatusOr<std::unique_ptr<KeysetHandle>> CreateAead256GcmSivKeyset() {
  // Tink provides pre-baked templetes. For example, we generate a key template
  // for AES256-GCM-SIV.
  KeyTemplate key_template = crypto::tink::AeadKeyTemplates::Aes256GcmSiv();
  // This will generate a new keyset with only *one* key and return a keyset
  // handle to it.
  return KeysetHandle::GenerateNew(key_template);
}

}  // namespace tink_walkthrough
// [END tink_walkthrough_create_keyset]
