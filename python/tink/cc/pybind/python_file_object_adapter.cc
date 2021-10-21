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

#include "tink/cc/python_file_object_adapter.h"

#include "absl/status/status.h"
#include "pybind11/pybind11.h"
#include "tink/cc/pybind/status_casters.h"

namespace crypto {
namespace tink {

// Defining PYBIND11_OVERLOAD macros here for now.
// TODO(b/146426040): Use future macros for OSS absl::Status, StatusOr
//                    when they become available.

// Macro to populate pybind11 trampoline class virtual methods with a
// util::Status return type. Converts all exceptions derived from
// std::exception to a StatusNotOk return. std::abort is called for
// all other exceptions, to ensure exceptions don't unwind through code
// compiled with -fno-exceptions (or similar, depending on the platform).
// Modeled after PYBIND11_OVERLOAD_INT defined in pybind11/pybind11.h.
#define PYBIND11_OVERLOAD_PURE_STATUS_RETURN(cname, name, ...)            \
  try {                                                                   \
    pybind11::gil_scoped_acquire gil;                                     \
    pybind11::function overload =                                         \
        pybind11::get_overload(static_cast<const cname *>(this), name);   \
    if (!overload) {                                                      \
      return util::Status(absl::StatusCode::kUnimplemented,               \
                          "No Python overload is defined for " name "."); \
    }                                                                     \
    overload(__VA_ARGS__); /* Ignoring return value. */                   \
    return util::Status();                                                \
  } catch (const std::exception &e) {                                     \
    return util::Status(util::error::UNKNOWN, e.what());                  \
  } catch (...) {                                                         \
    std::abort();                                                         \
  }

// Macro to populate pybind11 trampoline class virtual methods with a
// util::StatusOr return type. Converts all exceptions as described for
// PYBIND11_OVERLOAD_PURE_STATUS_RETURN.
#define PYBIND11_OVERLOAD_PURE_STATUSOR_RETURN(statusor_payload_type, cname, \
                                               name, ...)                    \
  try {                                                                      \
    pybind11::gil_scoped_acquire gil;                                        \
    pybind11::function overload =                                            \
        pybind11::get_overload(static_cast<const cname *>(this), name);      \
    if (!overload) {                                                         \
      return util::Status(absl::StatusCode::kUnimplemented,                  \
                          "No Python overload is defined for " name ".");    \
    }                                                                        \
    auto o = overload(__VA_ARGS__);                                          \
    return o.cast<statusor_payload_type>();                                  \
  } catch (const std::exception &e) {                                        \
    return util::Status(util::error::UNKNOWN, e.what());                     \
  } catch (...) {                                                            \
    std::abort();                                                            \
  }

class Pybind11PythonFileObjectAdapter : public PythonFileObjectAdapter {
 public:
  // Inherit the constructors.
  using PythonFileObjectAdapter::PythonFileObjectAdapter;

  // Trampoline for each virtual member function:

  util::StatusOr<int> Write(absl::string_view data) override{
      PYBIND11_OVERLOAD_PURE_STATUSOR_RETURN(
          int, PythonFileObjectAdapter, "write",
          pybind11::bytes(std::string(data)))}

  util::Status Close() override{
      PYBIND11_OVERLOAD_PURE_STATUS_RETURN(PythonFileObjectAdapter, "close")}

  util::StatusOr<std::string> Read(int size) override {
    PYBIND11_OVERLOAD_PURE_STATUSOR_RETURN(std::string, PythonFileObjectAdapter,
                                           "read", size)
  }
};

void PybindRegisterPythonFileObjectAdapter(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;

  // TODO(b/146492561): Reduce the number of complicated lambdas.
  py::class_<PythonFileObjectAdapter, Pybind11PythonFileObjectAdapter,
             std::shared_ptr<PythonFileObjectAdapter>>(
      m, "PythonFileObjectAdapter")
      .def(py::init<>())
      .def(
          "write",
          [](PythonFileObjectAdapter *self,
             const py::bytes &data) -> util::StatusOr<int> {
            return self->Write(std::string(data));  // TODO(b/145925674)
          },
          py::arg("data"))
      .def("close", &PythonFileObjectAdapter::Close)
      .def(
          "read",
          [](PythonFileObjectAdapter *self, int size)
              -> util::StatusOr<py::bytes> { return self->Read(size); },
          py::arg("size"));
}

}  // namespace tink
}  // namespace crypto
