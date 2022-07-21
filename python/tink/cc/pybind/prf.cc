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

#include "tink/cc/pybind/prf.h"

#include <algorithm>
#include <string>
#include <utility>

#include "pybind11/pybind11.h"
#include "tink/prf/prf_set.h"
#include "tink/util/statusor.h"
#include "tink/cc/pybind/tink_exception.h"

namespace crypto {
namespace tink {

using pybind11::google_tink::TinkException;

void PybindRegisterPrf(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;

  py::class_<Prf>(m, "Prf", "The interface for PRF.")
      // We only wrap PrfSet objects that contain a single PRF. Therefore, we
      // only need the function "compute_primary".
      .def(
          "compute",
          [](const Prf& self, const py::bytes& input_data,
             size_t output_length) -> py::bytes {
            // TODO(b/145925674)
            util::StatusOr<std::string> result =
                self.Compute(std::string(input_data), output_length);
            if (!result.ok()) {
              throw TinkException(result.status());
            }
            return *std::move(result);
          },
          py::arg("input_data"), py::arg("output_length"),
          "Computes the value of the primary (and only) PRF.");
}

}  // namespace tink
}  // namespace crypto
