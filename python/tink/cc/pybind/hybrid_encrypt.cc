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

#include "tink/cc/pybind/hybrid_encrypt.h"

#include <string>
#include <utility>

#include "pybind11/pybind11.h"
#include "tink/hybrid_encrypt.h"
#include "tink/util/statusor.h"
#include "tink/cc/pybind/tink_exception.h"

namespace crypto {
namespace tink {

using pybind11::google_tink::TinkException;

void PybindRegisterHybridEncrypt(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;

  // TODO(b/146492561): Reduce the number of complicated lambdas.
  py::class_<HybridEncrypt>(m, "HybridEncrypt")
      .def(
          "encrypt",
          [](const HybridEncrypt& self, const py::bytes& plaintext,
             const py::bytes& context_info) -> py::bytes {
            // TODO(b/145925674)
            util::StatusOr<std::string> encrypt_result =
                self.Encrypt(std::string(plaintext), std::string(context_info));
            if (!encrypt_result.ok()) {
              throw TinkException(encrypt_result.status());
            }
            return *std::move(encrypt_result);
          },
          py::arg("plaintext"), py::arg("context_info"));
}

}  // namespace tink
}  // namespace crypto
