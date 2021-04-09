// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_CONFIG_CONFIG_UTIL_H_
#define TINK_CONFIG_CONFIG_UTIL_H_

#include "proto/config.pb.h"

namespace crypto {
namespace tink {

google::crypto::tink::KeyTypeEntry CreateTinkKeyTypeEntry(
    const std::string& catalogue_name, const std::string& primitive_name,
    const std::string& key_proto_name, int key_manager_version,
    bool new_key_allowed);

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CONFIG_CONFIG_UTIL_H_
