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

#include "tink/cc/pybind/input_stream_adapter.h"

#include <string>
#include <utility>

#include "pybind11/pybind11.h"
#include "tink/cc/input_stream_adapter.h"
#include "tink/cc/pybind/tink_exception.h"

namespace crypto {
namespace tink {

namespace {

class TinkStreamFinishedException : public std::exception {
 public:
  explicit TinkStreamFinishedException(const crypto::tink::util::Status& status)
      : error_code_(static_cast<int>(status.code())),
        what_(status.ToString()) {}

  int error_code() const { return error_code_; }

  const char* what() const noexcept override { return what_.c_str(); }

 private:
  int error_code_;
  std::string what_;
};

}  // namespace

using pybind11::google_tink::TinkException;

void PybindRegisterInputStreamAdapter(pybind11::module* module) {
  namespace py = pybind11;
  py::module& m = *module;

  py::register_exception<TinkStreamFinishedException>(
      m, "PythonTinkStreamFinishedException");

  // TODO(b/146492561): Reduce the number of complicated lambdas.
  py::class_<InputStreamAdapter>(m, "InputStreamAdapter")
      .def(
          "read",
          [](InputStreamAdapter* self, int64_t size) -> py::bytes {
            util::StatusOr<std::string> read_result = self->Read(size);
            if (read_result.status().code() == absl::StatusCode::kOutOfRange) {
              throw TinkStreamFinishedException(
                  std::move(read_result).status());
            }
            if (!read_result.ok()) {
              throw TinkException(read_result.status());
            }
            return *std::move(read_result);
          },
          py::arg("size"));
}

}  // namespace tink
}  // namespace crypto
