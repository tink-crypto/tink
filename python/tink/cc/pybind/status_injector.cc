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

#include <pybind11/pybind11.h>

#include "absl/memory/memory.h"
#include "tink/util/status.h"
#include "tink/cc/pybind/status_casters.h"
#include "pybind11/detail/common.h"

namespace pybind11 {
namespace test {

namespace util = crypto::tink::util;

struct IntValue {
  IntValue() = default;
  IntValue(int value_in) : value(value_in) {}
  int value;
};

class TestClass {
 public:
  util::Status MakeStatus(util::error::Code code,
                          const std::string& text = "") {
    return util::Status(code, text);
  }

  util::Status MakeStatusConst(util::error::Code code,
                               const std::string& text = "") const {
    return util::Status(code, text);
  }

  util::StatusOr<int> MakeFailureStatusOr(util::error::Code code,
                                          const std::string& text = "") {
    return util::Status(code, text);
  }
};

bool CheckStatus(const util::Status& status, util::error::Code code) {
  return status.code() == static_cast<absl::StatusCode>(code);
}

util::Status ReturnStatus(util::error::Code code,
                          const std::string& text = "") {
  return util::Status(code, text);
}

pybind11::object ReturnStatusManualCast(util::error::Code code,
                                        const std::string& text = "") {
  return pybind11::cast(
      google_tink::DoNotThrowStatus(util::Status(code, text)));
}

const util::Status& ReturnStatusRef(util::error::Code code,
                                    const std::string& text = "") {
  static util::Status static_status;
  static_status = util::Status(code, text);
  return static_status;
}

const util::Status* ReturnStatusPtr(util::error::Code code,
                                    const std::string& text = "") {
  static util::Status static_status;
  static_status = util::Status(code, text);
  return &static_status;
}

util::StatusOr<int> ReturnFailureStatusOr(util::error::Code code,
                                          const std::string& text = "") {
  return util::Status(code, text);
}

pybind11::object ReturnFailureStatusOrManualCast(util::error::Code code,
                                                 const std::string& text = "") {
  return pybind11::cast(
      google_tink::DoNotThrowStatus(util::Status(code, text)));
}

util::StatusOr<int> ReturnValueStatusOr(int value) { return value; }

util::StatusOr<const IntValue*> ReturnPtrStatusOr(int value) {
  static IntValue static_object;
  static_object.value = value;
  return &static_object;
}

util::StatusOr<std::unique_ptr<IntValue>> ReturnUniquePtrStatusOr(int value) {
  return absl::make_unique<IntValue>(value);
}

util::StatusOr<std::string> ReturnAlphaBetaGammaEncoded() {
  return std::string("EDD4f89 alpha=\xce\xb1 beta=\xce\xb2 gamma=\xce\xb3");
}

void PybindRegisterStatusInjector(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;

  class_<IntValue>(m, "IntValue").def_readonly("value", &IntValue::value);

  class_<TestClass>(m, "TestClass")
      .def(init())
      .def("make_status",
           google_tink::DoNotThrowStatus(&TestClass::MakeStatus),
           arg("code"), arg("text") = "")
      .def("make_status_const",
           google_tink::DoNotThrowStatus(&TestClass::MakeStatusConst),
           arg("code"),
           arg("text") = "")
      .def("make_failure_status_or",
           google_tink::DoNotThrowStatus(&TestClass::MakeFailureStatusOr),
           arg("code"), arg("text") = "");

  // util::Status bindings
  m.def("check_status", &CheckStatus, arg("status"), arg("code"));
  m.def("return_status", &ReturnStatus, "Raise an error if code is not OK.",
        arg("code"), arg("text") = "");
  m.def("make_status", google_tink::DoNotThrowStatus(&ReturnStatus),
        "Return a status without raising an error, regardless of what it is.",
        arg("code"), arg("text") = "");
  m.def("make_status_manual_cast", ReturnStatusManualCast,
        "Return a status without raising an error, regardless of what it is.",
        arg("code"), arg("text") = "");
  m.def("make_status_ref", google_tink::DoNotThrowStatus(&ReturnStatusRef),
        "Return a reference to a static status value without raising an error.",
        arg("code"), arg("text") = "", return_value_policy::reference);
  m.def("make_status_ptr", google_tink::DoNotThrowStatus(&ReturnStatusPtr),
        "Return a reference to a static status value without raising an error.",
        arg("code"), arg("text") = "", return_value_policy::reference);

  // util::StatusOr bindings
  m.def("return_value_status_or", &ReturnValueStatusOr, arg("value"));
  m.def("return_failure_status_or", &ReturnFailureStatusOr,
        "Raise an error with the given code.", arg("code"), arg("text") = "");
  m.def("make_failure_status_or",
        google_tink::DoNotThrowStatus(&ReturnFailureStatusOr), arg("code"),
        arg("text") = "", "Return a status without raising an error.");
  m.def("make_failure_status_or_manual_cast", &ReturnFailureStatusOrManualCast,
        arg("code"), arg("text") = "", "Return a status.");
  m.def("return_ptr_status_or", &ReturnPtrStatusOr, arg("value"),
        "Return a reference in a status or to a static value.",
        return_value_policy::reference);
  m.def("return_unique_ptr_status_or", &ReturnUniquePtrStatusOr, arg("value"));
  m.def("return_alpha_beta_gamma_decoded", &ReturnAlphaBetaGammaEncoded);
  m.def("return_alpha_beta_gamma_encoded",
        []() -> util::StatusOr<bytes> {
          return ReturnAlphaBetaGammaEncoded();
        });
}

}  // namespace test
}  // namespace pybind11
