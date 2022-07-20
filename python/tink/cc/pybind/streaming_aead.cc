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

#include "tink/cc/pybind/streaming_aead.h"

#include "pybind11/pybind11.h"
#include "tink/streaming_aead.h"

namespace crypto {
namespace tink {

void PybindRegisterStreamingAead(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;

  namespace py = pybind11;

  py::class_<StreamingAead>(
      m, "StreamingAead",
      "Interface for streaming authenticated encryption with associated data. "
      "Streaming encryption is typically used for encrypting large plaintexts "
      "such as large files. This interface supports a streaming interface for "
      "symmetric encryption with authentication. The underlying encryption "
      "modes "
      "are selected so that partial plaintext can be obtained fast by "
      "decrypting "
      "and authenticating just a part of the ciphertext.")

      // Intentionally empty.
      //
      // The wrapped CC primitive's only purpose is to be stored as a member
      // variable and later be passed to a wrapper function (which sidesteps
      // wrapped an OutputStream). Therefore Python doesn't need to know about
      // its methods, just that it exists.
      ;  // NOLINT
}

}  // namespace tink
}  // namespace crypto
