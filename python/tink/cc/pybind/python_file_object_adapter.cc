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

#include "tink/cc/pybind/python_file_object_adapter.h"

#include <string>

#include "absl/status/status.h"
#include "pybind11/pybind11.h"
#include "tink/cc/pybind/status_casters.h"
#include "tink/cc/python_file_object_adapter.h"

namespace crypto {
namespace tink {

class Pybind11PythonFileObjectAdapter : public PythonFileObjectAdapter {
 public:
  // Inherit the constructors.
  using PythonFileObjectAdapter::PythonFileObjectAdapter;

  // Trampoline for each virtual member function.

  // The implementations are modeled after PYBIND11_OVERLOAD_INT
  // defined in pybind11/pybind11.h, and convert all exceptions derived from
  // std::exception to a StatusNotOk return. std::abort is called for all other
  // exceptions, to ensure exceptions don't unwind through code compiled with
  // -fno-exceptions (or similar, depending on the platform).

  util::StatusOr<int> Write(absl::string_view data) override {
    try {
      pybind11::gil_scoped_acquire gil;
      pybind11::function overload = pybind11::get_overload(
          static_cast<const PythonFileObjectAdapter *>(this), "write");
      if (!overload) {
        return util::Status(absl::StatusCode::kUnimplemented,
                            "No Python overload is defined for write.");
      }
      auto o = overload(pybind11::bytes(std::string(data)));
      return o.cast<int>();
    } catch (const std::exception &e) {
      return util::Status(absl::StatusCode::kUnknown, e.what());
    } catch (...) {
      std::abort();
    }
  }

  util::Status Close() override {
    try {
      pybind11::gil_scoped_acquire gil;
      pybind11::function overload = pybind11::get_overload(
          static_cast<const PythonFileObjectAdapter *>(this), "close");
      if (!overload) {
        return util::Status(absl::StatusCode::kUnimplemented,
                            "No Python overload is defined for close.");
      }
      overload(); /* Ignoring return value. */
      return util::Status();
    } catch (const std::exception &e) {
      return util::Status(absl::StatusCode::kUnknown, e.what());
    } catch (...) {
      std::abort();
    }
  }

  util::StatusOr<std::string> Read(int size) override {
    try {
      pybind11::gil_scoped_acquire gil;
      pybind11::function overload = pybind11::get_overload(
          static_cast<const PythonFileObjectAdapter *>(this), "read");
      if (!overload) {
        return util::Status(absl::StatusCode::kUnimplemented,
                            "No Python overload is defined for read.");
      }
      auto o = overload(size);
      return o.cast<std::string>();
    } catch (const std::exception &e) {
      return util::Status(absl::StatusCode::kUnknown, e.what());
    } catch (...) {
      std::abort();
    }
  }
};

void PybindRegisterPythonFileObjectAdapter(pybind11::module *module) {
  namespace py = pybind11;
  py::module &m = *module;

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
