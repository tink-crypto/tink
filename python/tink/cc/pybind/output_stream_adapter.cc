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
#include "tink/cc/pybind/output_stream_adapter.h"

#include <algorithm>
#include <string>
#include <utility>

#include "pybind11/pybind11.h"
#include "tink/cc/output_stream_adapter.h"
#include "tink/cc/pybind/tink_exception.h"

namespace crypto {
namespace tink {

using pybind11::google_tink::TinkException;

void PybindRegisterOutputStreamAdapter(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;

  // TODO(b/146492561): Reduce the number of complicated lambdas.
  py::class_<OutputStreamAdapter>(m, "OutputStreamAdapter")
      .def(
          "write",
          [](OutputStreamAdapter* self, const py::bytes& data) -> int64_t {
            util::StatusOr<int64_t> result = self->Write(std::string(data));
            if (!result.ok()) {
              throw TinkException(result.status());
            }
            return *std::move(result);
          },
          py::arg("data"))
      .def("close", [](OutputStreamAdapter* self) -> void {
        util::Status result = self->Close();
        if (!result.ok()) {
          throw TinkException(result);
        }
      });
}

}  // namespace tink
}  // namespace crypto
