// Copyright 2019 Google LLC.
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

#ifndef TINK_PYTHON_UTIL_CLIF_H_
#define TINK_PYTHON_UTIL_CLIF_H_

#include <assert.h>
#include "clif/python/types.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
// placeholder_pyobject_h, please ignore

// CLIF use `::crypto::tink::util::Status` as Status
// CLIF use `::crypto::tink::util::StatusOr` as StatusOr

namespace crypto {
namespace tink {
namespace util {

PyObject* Get_UtilStatusOk();
void ErrorFromStatus(const Status& status);
Status StatusFromPyException();
std::string PyExcFetch();

PyObject* Clif_PyObjFrom(const Status& c, const ::clif::py::PostConv&);

// Note: there is no corresponding PyObjAs for util::Status, as this class is
// represented on the Python side by an exception. This implies that it is not
// possible to hand a util::Status to C++. Pass a code and message instead.

template <typename T>
PyObject* Clif_PyObjFrom(const StatusOr<T>& c, const ::clif::py::PostConv& pc) {
  if (!c.ok()) {
    ErrorFromStatus(c.status());
    return nullptr;
  } else {
    using ::clif::Clif_PyObjFrom;
    return Clif_PyObjFrom(c.ValueOrDie(), pc.Get(0));
  }
}

template <typename T>
PyObject* Clif_PyObjFrom(StatusOr<T>&& c,  // NOLINT:c++11
                         const ::clif::py::PostConv& pc) {
  if (!c.ok()) {
    ErrorFromStatus(c.status());
    return nullptr;
  } else {
    using ::clif::Clif_PyObjFrom;
    return Clif_PyObjFrom(std::move(c).ValueOrDie(), pc.Get(0));
  }
}

template<typename T>
bool Clif_PyObjAs(PyObject* p, StatusOr<T>* c) {
  assert(c != nullptr);

  if (PyErr_Occurred()) {
    *c = StatusFromPyException();
    return true;
  }

  T val;
  using ::clif::Clif_PyObjAs;
  if (Clif_PyObjAs(p, &val)) {
    *c = std::move(val);
    return true;
  }

  return false;
}

}  // namespace util
}  // namespace tink
}  // namespace crypto

namespace clif {
namespace callback {

// Specialization of a generic Clif Python callback handling for a
// function returning util::StatusOr.
template <typename T>
class ReturnValue<::crypto::tink::util::StatusOr<T>> {
 public:
  ::crypto::tink::util::StatusOr<T> FromPyValue(PyObject* result) {
    ::crypto::tink::util::StatusOr<T> v;
    bool ok = Clif_PyObjAs(result, &v);
    Py_XDECREF(result);
    if (!ok) {
      v = ::crypto::tink::util::StatusFromPyException();
    }
    return v;
  }
};

// Specialization of a generic Clif Python callback handling for a
// function returning a util::Status.
template <>
class ReturnValue<::crypto::tink::util::Status> {
 public:
  ::crypto::tink::util::Status FromPyValue(PyObject* result) {
    Py_XDECREF(result);
    if (PyErr_Occurred()) {
      return ::crypto::tink::util::StatusFromPyException();
    }
    return ::crypto::tink::util::OkStatus();
  }
};

}  // namespace callback
}  // namespace clif

#endif  // TINK_PYTHON_UTIL_CLIF_H_
