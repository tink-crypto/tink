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
#ifndef TINK_EXAMPLES_WALKTHROUGH_CREATE_KEYSET_H_
#define TINK_EXAMPLES_WALKTHROUGH_CREATE_KEYSET_H_

#include <memory>

#include "tink/keyset_handle.h"
#include "tink/util/statusor.h"

namespace tink_walkthrough {

// Creates a keyset with a single AES256-GCM-SIV key and return a handle to it.
crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::KeysetHandle>>
CreateAead256GcmSivKeyset();

}  // namespace tink_walkthrough

#endif  // TINK_EXAMPLES_WALKTHROUGH_CREATE_KEYSET_H_
