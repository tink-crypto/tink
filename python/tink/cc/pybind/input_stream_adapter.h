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
#ifndef TINK_PYTHON_TINK_CC_PYBIND_INPUT_STREAM_ADAPTER_H_
#define TINK_PYTHON_TINK_CC_PYBIND_INPUT_STREAM_ADAPTER_H_

#include "pybind11/pybind11.h"

namespace crypto {
namespace tink {

void PybindRegisterInputStreamAdapter(pybind11::module* m);

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PYTHON_TINK_CC_PYBIND_INPUT_STREAM_ADAPTER_H_
