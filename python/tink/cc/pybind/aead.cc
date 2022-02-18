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

#include "tink/cc/pybind/aead.h"

#include <string>
#include <utility>

#include "pybind11/pybind11.h"
#include "tink/aead.h"
#include "tink/util/statusor.h"
#include "tink/cc/pybind/tink_exception.h"

namespace crypto {
namespace tink {

using pybind11::google_tink::TinkException;

void PybindRegisterAead(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;

  // TODO(b/146492561): Reduce the number of complicated lambdas.
  py::class_<Aead>(
      m, "Aead",
      "The interface for authenticated encryption with associated data. "
      "Implementations of this interface are secure against adaptive "
      "chosen ciphertext attacks.  Encryption with associated data ensures "
      "authenticity and integrity of that data, but not its secrecy. "
      "(see RFC 5116, https://tools.ietf.org/html/rfc5116)")

      .def(
          "encrypt",
          [](const Aead &self, const py::bytes &plaintext,
             const py::bytes &associated_data) -> py::bytes {
            util::StatusOr<std::string> result = self.Encrypt(
                std::string(plaintext), std::string(associated_data));
            if (!result.ok()) {
              throw TinkException(result.status());
            }
            return *std::move(result);
          },
          py::arg("plaintext"), py::arg("associated_data"),
          "Encrypts 'plaintext' with 'associated_data' as associated data, "
          "and returns the resulting ciphertext. "
          "The ciphertext allows for checking authenticity and integrity "
          "of the associated data, but does not guarantee its secrecy.")
      .def(
          "decrypt",
          [](const Aead &self, const py::bytes &ciphertext,
             const py::bytes &associated_data) -> py::bytes {
            // TODO(b/145925674)
            util::StatusOr<std::string> result = self.Decrypt(
                std::string(ciphertext), std::string(associated_data));
            if (!result.ok()) {
              throw TinkException(result.status());
            }
            return *std::move(result);
          },
          py::arg("ciphertext"), py::arg("associated_data"),
          "Decrypts 'ciphertext' with 'associated_data' as associated data, "
          "and returns the resulting plaintext. "
          "The decryption verifies the authenticity and integrity "
          "of the associated data, but there are no guarantees wrt. secrecy "
          "of that data.");
}

}  // namespace tink
}  // namespace crypto
