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

#include "tink/hybrid_encrypt.h"

#include <string>

#include "pybind11/pybind11.h"
#include "tink/util/statusor.h"
#include "tink/cc/pybind/status_casters.h"

namespace crypto {
namespace tink {

void PybindRegisterHybridEncrypt(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;

  // TODO(b/146492561): Reduce the number of complicated lambdas.
  py::class_<HybridEncrypt>(m, "HybridEncrypt")
      .def(
          "encrypt",
          [](const HybridEncrypt& self, const py::bytes& plaintext,
             const py::bytes& context_info) -> util::StatusOr<py::bytes> {
            // TODO(b/145925674)
            return self.Encrypt(std::string(plaintext),
                                std::string(context_info));
          },
          py::arg("plaintext"), py::arg("context_info"));
}

}  // namespace tink
}  // namespace crypto
