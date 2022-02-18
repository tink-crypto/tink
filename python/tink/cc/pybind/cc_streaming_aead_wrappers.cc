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

#include "tink/cc/pybind/cc_streaming_aead_wrappers.h"

#include <string>
#include <utility>

#include "pybind11/pybind11.h"
#include "tink/cc/cc_streaming_aead_wrappers.h"
#include "tink/cc/pybind/import_helper.h"
#include "tink/cc/pybind/tink_exception.h"

namespace crypto {
namespace tink {

using pybind11::google_tink::TinkException;

void PybindRegisterCcStreamingAeadWrappers(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;

  // TODO(b/146492561): Reduce the number of complicated lambdas.
  m.def(
      "new_cc_encrypting_stream",
      // TODO(b/145925674)
      [](StreamingAead* streaming_aead, const py::bytes& aad,
         std::shared_ptr<PythonFileObjectAdapter> ciphertext_destination)
          -> std::unique_ptr<OutputStreamAdapter> {
        util::StatusOr<std::unique_ptr<OutputStreamAdapter>> result_stream =
            NewCcEncryptingStream(streaming_aead, std::string(aad),
                                  ciphertext_destination);
        if (!result_stream.ok()) {
          throw TinkException(result_stream.status());
        }
        return *std::move(result_stream);
      },
      py::arg("primitive"), py::arg("aad"), py::arg("destination"),
      // Keep destination alive at least as long as OutputStreamAdapter.
      py::keep_alive<0, 3>());

  m.def(
      "new_cc_decrypting_stream",
      // TODO(b/145925674)
      [](StreamingAead* streaming_aead, const py::bytes& aad,
         std::shared_ptr<PythonFileObjectAdapter> ciphertext_source)
          -> std::unique_ptr<InputStreamAdapter> {
        util::StatusOr<std::unique_ptr<InputStreamAdapter>> result_stream =
            NewCcDecryptingStream(streaming_aead, std::string(aad),
                                  ciphertext_source);
        if (!result_stream.ok()) {
          throw TinkException(result_stream.status());
        }
        return *std::move(result_stream);
      },
      py::arg("primitive"), py::arg("aad"), py::arg("source"),
      // Keep source alive at least as long as InputStreamAdapter.
      py::keep_alive<0, 3>());
}

}  // namespace tink
}  // namespace crypto
