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

#include "tink/internal/key_info.h"

namespace crypto {
namespace tink {

using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeysetInfo;

KeysetInfo::KeyInfo KeyInfoFromKey(const Keyset::Key& key) {
  KeysetInfo::KeyInfo key_info;
  key_info.set_key_id(key.key_id());
  key_info.set_type_url(key.key_data().type_url());
  key_info.set_output_prefix_type(key.output_prefix_type());
  key_info.set_status(key.status());
  return key_info;
}

KeysetInfo KeysetInfoFromKeyset(const Keyset& keyset) {
  KeysetInfo keyset_info;
  keyset_info.set_primary_key_id(keyset.primary_key_id());
  for (const Keyset::Key& key : keyset.key()) {
    *keyset_info.add_key_info() = KeyInfoFromKey(key);
  }
  return keyset_info;
}

}  // namespace tink
}  // namespace crypto
