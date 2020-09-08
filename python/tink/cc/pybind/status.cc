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

#include <pybind11/detail/common.h>
#include <pybind11/pybind11.h>

#include <exception>
#include <stdexcept>

#include "tink/util/status.h"
#include "tink/cc/pybind/status_utils.h"

namespace pybind11 {
namespace google_tink {

namespace util = crypto::tink::util;

// Returns false if status_or represents a non-ok status object, and true in all
// other cases (including the case that this is passed a non-status object).
bool IsOk(handle status_or) {
  detail::make_caster<util::Status> caster;
  // "Not a status" means "ok" for StatusOr.
  if (!caster.load(status_or, true)) return true;
  return static_cast<util::Status &>(caster).ok();
}

void PybindRegisterStatus(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;

  enum_<util::error::Code>(m, "ErrorCode")
      .value("OK", util::error::Code::OK)
      .value("CANCELLED", util::error::Code::CANCELLED)
      .value("UNKNOWN", util::error::Code::UNKNOWN)
      .value("INVALID_ARGUMENT", util::error::Code::INVALID_ARGUMENT)
      .value("DEADLINE_EXCEEDED", util::error::Code::DEADLINE_EXCEEDED)
      .value("NOT_FOUND", util::error::Code::NOT_FOUND)
      .value("ALREADY_EXISTS", util::error::Code::ALREADY_EXISTS)
      .value("PERMISSION_DENIED", util::error::Code::PERMISSION_DENIED)
      .value("RESOURCE_EXHAUSTED", util::error::Code::RESOURCE_EXHAUSTED)
      .value("FAILED_PRECONDITION", util::error::Code::FAILED_PRECONDITION)
      .value("ABORTED", util::error::Code::ABORTED)
      .value("OUT_OF_RANGE", util::error::Code::OUT_OF_RANGE)
      .value("UNIMPLEMENTED", util::error::Code::UNIMPLEMENTED)
      .value("INTERNAL", util::error::Code::INTERNAL)
      .value("UNAVAILABLE", util::error::Code::UNAVAILABLE)
      .value("DATA_LOSS", util::error::Code::DATA_LOSS);

  class_<util::Status>(m, "Status")
      .def(init())
      .def(init<util::error::Code, std::string>())
      .def("ok", &util::Status::ok)
      .def("error_code", &util::Status::error_code)
      .def("error_message", &util::Status::error_message)
      .def("to_string", &util::Status::ToString)
      .def("__repr__", &util::Status::ToString);

  m.def("is_ok", &IsOk, arg("status_or"),
        "Returns false only if passed a non-ok status; otherwise returns true. "
        "This can be used on the return value of a function which returns a "
        "StatusOr without raising an exception. The .ok() method cannot be "
        "used in this case because an ok status is never returned; instead, a "
        "non-status object is returned, which doesn't have a .ok() method.");

  // Because status_casters has not been included, the functions below will
  // return a wrapped status, not raise an exception.
  // Note that we cannot include status_casters here because that imports this
  // module and therefore would create a circular dependency.

  // Register the exception.
  static pybind11::exception<StatusNotOk> status_not_ok(m, "StatusNotOk");

  // Register a custom handler which converts a C++ StatusNotOk to a python
  // StatusNotOk exception and adds the status field.
  register_exception_translator([](std::exception_ptr p) {
    try {
      if (p) std::rethrow_exception(p);
    } catch (const StatusNotOk &e) {
      status_not_ok.attr("status") = cast(e.status());
      status_not_ok(e.what());
    }
  });
}

}  // namespace google_tink
}  // namespace pybind11
