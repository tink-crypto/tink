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

#include "tink/cc/pybind/public_key_verify.h"

#include <string>

#include "pybind11/pybind11.h"
#include "tink/public_key_verify.h"
#include "tink/util/status.h"
#include "tink/cc/pybind/status_casters.h"

namespace crypto {
namespace tink {

void PybindRegisterPublicKeyVerify(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;

  // TODO(b/146492561): Reduce the number of complicated lambdas.
  py::class_<PublicKeyVerify>(
      m, "PublicKeyVerify",
      "Interface for public key verifying. "
      "Digital Signatures provide functionality of signing data and "
      "verification of the signatures. They are represented by a pair of "
      "primitives (interfaces) 'PublicKeySign' for signing of data, and "
      "'PublicKeyVerify' for verification of signatures. Implementations of "
      "these interfaces are secure against adaptive chosen-message attacks. "
      "Signing data ensures the authenticity and the integrity of that data, "
      "but not its secrecy.")

      .def(
          "verify",
          [](const PublicKeyVerify& self, const py::bytes& signature,
             const py::bytes& data) -> util::Status {
            // TODO(b/145925674)
            return self.Verify(std::string(signature), std::string(data));
          },
          py::arg("signature"), py::arg("data"),
          "Verifies that signature is a digital signature for data.");
}

}  // namespace tink
}  // namespace crypto
