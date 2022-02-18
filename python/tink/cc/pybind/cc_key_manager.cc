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

#include "tink/cc/pybind/cc_key_manager.h"

#include <memory>

#include "pybind11/pybind11.h"
#include "tink/aead.h"
#include "tink/deterministic_aead.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/mac.h"
#include "tink/prf/prf_set.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/streaming_aead.h"
#include "tink/cc/cc_key_manager.h"
#include "tink/cc/pybind/import_helper.h"

namespace crypto {
namespace tink {

namespace py_thin_wrappers {

template <typename PrimitiveType>
std::unique_ptr<pybind11::class_<CcKeyManager<PrimitiveType>>> WrapCcKeyManager(
    pybind11::module& m, const char* py_class_name,
    const char* py_class_docstring, const char* primitive_module_name) {
  namespace py = pybind11;
  auto cls = absl::make_unique<py::class_<CcKeyManager<PrimitiveType>>>(
      m, py_class_name, py_class_docstring);
  cls->def_static("from_cc_registry",
                  &CcKeyManager<PrimitiveType>::GetFromCcRegistry);
  cls->def("primitive", &CcKeyManager<PrimitiveType>::GetPrimitive,
           py::arg("serialized_key_data"));
  cls->def("key_type", &CcKeyManager<PrimitiveType>::KeyType);
  cls->def("new_key_data", &CcKeyManager<PrimitiveType>::NewKeyData,
           py::arg("serialized_key_template"));
  return cls;
}

}  // namespace py_thin_wrappers

void PybindRegisterCcKeyManager(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;

  py_thin_wrappers::WrapCcKeyManager<Aead>(
      m, "AeadKeyManager",
      "Key Manager for AEAD (authenticated encryption with associated data).",
      "aead");
  py_thin_wrappers::WrapCcKeyManager<DeterministicAead>(
      m, "DeterministicAeadKeyManager", "Key Manager for Deterministic AEAD.",
      "deterministic_aead");
  py_thin_wrappers::WrapCcKeyManager<StreamingAead>(
      m, "StreamingAeadKeyManager", "Key Manager for Streaming AEAD.",
      "streaming_aead");
  py_thin_wrappers::WrapCcKeyManager<HybridDecrypt>(
      m, "HybridDecryptKeyManager", "Key Manager for HybridDecrypt.",
      "hybrid_decrypt")
      ->def("public_key_data", &CcKeyManager<HybridDecrypt>::GetPublicKeyData,
            py::arg("key_data"));
  py_thin_wrappers::WrapCcKeyManager<HybridEncrypt>(
      m, "HybridEncryptKeyManager", "Key Manager for HybridEncrypt.",
      "hybrid_encrypt");
  py_thin_wrappers::WrapCcKeyManager<Mac>(
      m, "MacKeyManager", "Key Manager for MAC (message authentication code).",
      "mac");
  py_thin_wrappers::WrapCcKeyManager<Prf>(
      m, "PrfKeyManager", "Key Manager for Prf.", "prf");
  py_thin_wrappers::WrapCcKeyManager<PublicKeySign>(
      m, "PublicKeySignKeyManager", "Key Manager for Public Key signing.",
      "public_key_sign")
      ->def("public_key_data", &CcKeyManager<PublicKeySign>::GetPublicKeyData,
            py::arg("key_data"));
  py_thin_wrappers::WrapCcKeyManager<PublicKeyVerify>(
      m, "PublicKeyVerifyKeyManager",
      "Key Manager for Public Key verification.", "public_key_verify");
}

}  // namespace tink
}  // namespace crypto
