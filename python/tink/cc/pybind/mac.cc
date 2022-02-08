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

#include "tink/mac.h"

#include <string>

#include "pybind11/pybind11.h"
#include "tink/util/status.h"
#include "tink/cc/pybind/status_casters.h"

namespace crypto {
namespace tink {

void PybindRegisterMac(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;


  // TODO(b/146492561): Reduce the number of complicated lambdas.
  py::class_<Mac>(
      m, "Mac",
      "Interface for MACs (Message Authentication Codes). "
      "This interface should be used for authentication only, and not for "
      "other purposes (e.g., it should not be used to generate pseudorandom "
      "bytes).")

      .def(
          "compute_mac",
          [](const Mac& self,
             const py::bytes& data) -> util::StatusOr<py::bytes> {
            // TODO(b/145925674)
            return self.ComputeMac(std::string(data));
          },
          py::arg("data"),
          "Computes and returns the message authentication code (MAC) for "
          "'data'.")
      .def(
          "verify_mac",
          [](const Mac& self, const py::bytes& mac,
             const py::bytes& data) -> util::Status {
            // TODO(b/145925674)
            return self.VerifyMac(std::string(mac), std::string(data));
          },
          py::arg("mac"), py::arg("data"),
          "Verifies if 'mac' is a correct authentication code (MAC) for "
          "'data'. "
          "Raises a StatusNotOk exception if the verification fails.");
}

}  // namespace tink
}  // namespace crypto
