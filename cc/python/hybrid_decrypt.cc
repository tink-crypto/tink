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

#include "tink/hybrid_decrypt.h"

#include "third_party/pybind11/include/pybind11/pybind11.h"
#include "third_party/pybind11_abseil/absl_casters.h"
#include "tink/util/statusor.h"
#include "tink/python/cc/clif/status_casters.h"

namespace crypto {
namespace tink {

PYBIND11_MODULE(hybrid_decrypt, m) {
  namespace py = pybind11;

  // TODO(b/146492561): Reduce the number of complicated lambdas.
  py::class_<HybridDecrypt>(m, "HybridDecrypt")
      .def(
          "decrypt",
          [](const HybridDecrypt& self, const py::bytes& ciphertext,
             const py::bytes& context_info) -> util::StatusOr<py::bytes> {
            // TODO(b/145925674)
            return self.Decrypt(std::string(ciphertext),
                                std::string(context_info));
          },
          py::arg("ciphertext"), py::arg("context_info"));
}

}  // namespace tink
}  // namespace crypto
