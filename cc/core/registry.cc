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

#include "cc/registry.h"

#include <mutex>  // NOLINT(build/c++11)

namespace crypto {
namespace tink {

std::mutex Registry::maps_mutex_;
Registry::LabelToObjectMap Registry::type_to_manager_map_;
Registry::LabelToTypeNameMap Registry::type_to_primitive_map_;
Registry::LabelToObjectMap Registry::name_to_catalogue_map_;
Registry::LabelToTypeNameMap Registry::name_to_primitive_map_;

void Registry::Reset() {
  std::lock_guard<std::mutex> lock(maps_mutex_);
  type_to_manager_map_.clear();
  type_to_primitive_map_.clear();
  name_to_catalogue_map_.clear();
  name_to_primitive_map_.clear();
}



}  // namespace tink
}  // namespace crypto
