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

#include "tink/deterministic_aead.h"

#include <string>

#include "pybind11/pybind11.h"
#include "tink/util/statusor.h"
#include "tink/cc/pybind/status_casters.h"

namespace crypto {
namespace tink {

void PybindRegisterDeterministicAead(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;

  // TODO(b/146492561): Reduce the number of complicated lambdas.
  py::class_<DeterministicAead>(
      m, "DeterministicAead",
      "Interface for Deterministic Authenticated Encryption with Associated "
      "Data (Deterministic AEAD)\n",
      "For why this interface is desirable and some of its use cases, see for ",
      "example https://tools.ietf.org/html/rfc5297#section-1.3.\n", "Warning! ",
      "Unlike Aead, implementations of this interface are not semantically ",
      "secure, because encrypting the same plaintex always yields the same ",
      "ciphertext.\n", "Security guarantees\n",
      "Implementations of this interface provide 128-bit security level "
      "against ",
      "multi-user attacks with up to 2^32 keys. That means if an adversary ",
      "obtains 2^32 ciphertexts of the same message encrypted under 2^32 "
      "keys, ",
      "they need to do 2^128 computations to obtain a single key.\n",
      "Encryption with associated data ensures authenticity (who the sender "
      "is) ",
      "and integrity (the data has not been tampered with) of that data, but "
      "not ",
      "its secrecy. (see https://tools.ietf.org/html/rfc5116)")

      .def(
          "encrypt_deterministically",
          [](const DeterministicAead& self, const py::bytes& plaintext,
             const py::bytes& associated_data) -> util::StatusOr<py::bytes> {
            // TODO(b/145925674)
            return self.EncryptDeterministically(std::string(plaintext),
                                                 std::string(associated_data));
          },
          py::arg("plaintext"), py::arg("associated_data"))
      .def(
          "decrypt_deterministically",
          [](const DeterministicAead& self, const py::bytes& ciphertext,
             const py::bytes& associated_data) -> util::StatusOr<py::bytes> {
            // TODO(b/145925674)
            return self.DecryptDeterministically(std::string(ciphertext),
                                                 std::string(associated_data));
          },
          py::arg("ciphertext"), py::arg("associated_data"));
}

}  // namespace tink
}  // namespace crypto
