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

#include "tink/cc/pybind/public_key_sign.h"

#include <string>
#include <utility>

#include "pybind11/pybind11.h"
#include "tink/public_key_sign.h"
#include "tink/util/statusor.h"
#include "tink/cc/pybind/tink_exception.h"

namespace crypto {
namespace tink {

using pybind11::google_tink::TinkException;

void PybindRegisterPublicKeySign(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;

  // TODO(b/146492561): Reduce the number of complicated lambdas.
  py::class_<PublicKeySign>(
      m, "PublicKeySign",
      "Interface for public key signing. "
      "Digital Signatures provide functionality of signing data and "
      "verification of the signatures. They are represented by a pair of "
      "primitives (interfaces) 'PublicKeySign' for signing of data, and "
      "'PublicKeyVerify' for verification of signatures. Implementations of "
      "these interfaces are secure against adaptive chosen-message attacks. "
      "Signing data ensures the authenticity and the integrity of that data, "
      "but not its secrecy.")

      .def(
          "sign",
          [](const PublicKeySign& self,
             const py::bytes& data) -> py::bytes {
            // TODO(b/145925674)
            util::StatusOr<std::string> result = self.Sign(std::string(data));
            if (!result.ok()) {
              throw TinkException(result.status());
            }
            return *std::move(result);
          },
          py::arg("data"), "Computes the signature for 'data'.");
}

}  // namespace tink
}  // namespace crypto
