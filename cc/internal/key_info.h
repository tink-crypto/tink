// Copyright 2020 Google LLC
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
#ifndef TINK_INTERNAL_KEY_INFO_H_
#define TINK_INTERNAL_KEY_INFO_H_

#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

google::crypto::tink::KeysetInfo::KeyInfo KeyInfoFromKey(
    const google::crypto::tink::Keyset::Key& key);

google::crypto::tink::KeysetInfo KeysetInfoFromKeyset(
    const google::crypto::tink::Keyset& keyset);

}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_KEY_INFO_H_
