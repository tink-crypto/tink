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

#ifndef TINK_PYTHON_TINK_CC_PYBIND_IMPORT_HELPER_H_
#define TINK_PYTHON_TINK_CC_PYBIND_IMPORT_HELPER_H_

#include <string>

namespace crypto {
namespace tink {

// relative_import_path is relative to the tink directory, e.g.,
// "python.cc.pybind.cc_key_manager". The absolute import path to the
// tink directory is determined via a define in import_helper.cc.
void ImportTinkPythonModule(const std::string& relative_import_path);

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PYTHON_TINK_CC_PYBIND_IMPORT_HELPER_H_
