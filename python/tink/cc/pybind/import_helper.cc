// Copyright 2019 Google Inc.
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

#include "tink/cc/pybind/import_helper.h"

#include <pybind11/pybind11.h>
#include <string>

#include "absl/strings/str_cat.h"



namespace crypto {
namespace tink {

void ImportTinkPythonModule(const std::string& relative_import_path) {
  std::string full_path = "tink";
  if (!relative_import_path.empty()) {
    absl::StrAppend(&full_path, ".", relative_import_path);
  }
  pybind11::module::import(full_path.c_str());
}

}  // namespace tink
}  // namespace crypto
