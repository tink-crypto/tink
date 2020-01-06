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

#include "tink/python/cc/clif/import_helper.h"

#include <pybind11/pybind11.h>

#include <string>

// The value of THIRD_PARTY_TINK_PYTHON_IMPORT_PATH will be different depending
// on whether this is being built inside or outside of google3. The value used
// inside of google3 is defined here. Outside of google3, change this value by
// passing "-DTHIRD_PARTY_TINK_PYTHON_IMPORT_PATH=..." on the commandline.
#ifndef THIRD_PARTY_TINK_PYTHON_IMPORT_PATH
#define THIRD_PARTY_TINK_PYTHON_IMPORT_PATH google3.third_party.tink
#endif

namespace crypto {
namespace tink {

void ImportTinkPythonModule(const char* relative_import_path) {
  std::string full_path =
      PYBIND11_TOSTRING(THIRD_PARTY_TINK_PYTHON_IMPORT_PATH);
  if (relative_import_path && (*relative_import_path)) {
    full_path += ".";
    full_path += relative_import_path;
  }
  pybind11::module::import(full_path.c_str());
}

}  // namespace tink
}  // namespace crypto
