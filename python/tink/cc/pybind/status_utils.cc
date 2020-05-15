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

#include "tink/cc/pybind/status_utils.h"

#include <pybind11/pybind11.h>

#include "tink/cc/pybind/import_helper.h"

namespace pybind11 {
namespace google {

void ImportStatusModule() {
  // This function is called each time a Status object is passed from
  // C++ to Python or vice versa. While it is safe to call module::import
  // on an already-imported module, this is a super simple optimization
  // certain to cut out any overhead.
  static bool imported_already = false;
  if (!imported_already) {
    // crypto::tink::ImportTinkPythonModule("python.tink.cc.pybind.status");
    imported_already = true;
  }
}

}  // namespace google
}  // namespace pybind11
