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

#include "tink/python/util/clif.h"

#include <assert.h>
#include "absl/strings/str_cat.h"
#include "tink/util/status.h"



namespace crypto {
namespace tink {
namespace util {

PyObject* Get_UtilStatusOk() {
  static PyObject* const kUtilStatusOk = _PyObject_New(&PyBaseObject_Type);
  // TODO(mrovner): The following return is sligthly wrong:
  // In the (unlikely) case where the allocation failed, subsequent calls to
  // this function will return null without setting a Python exception.
  Py_XINCREF(kUtilStatusOk);
  return kUtilStatusOk;
}

void ErrorFromStatus(const Status& status) {
  /* Can't just do this
       static PyObject* const kUtilStatusError = ImportFQName(...
     because static creates a C++ lock around the whole statement and GIL can be
     elsewhere due to Python import. */
  static PyObject* kUtilStatusError = nullptr;
  if (kUtilStatusError == nullptr) {
    // Worst case it will do ImportFQName K times (K==number of threads)
    // which is OK.
    kUtilStatusError =
        clif::ImportFQName("google3.util.task.python.error.StatusNotOk");
    assert(kUtilStatusError != nullptr);
  }
  PyObject* message_set_object;
  message_set_object = Py_None;
  Py_INCREF(message_set_object);
  PyObject* err = Py_BuildValue(
      "is#siN", status.error_code(), status.error_message().data(),
      status.error_message().size(), "Not implemented!",
      status.CanonicalCode(), message_set_object);
  if (err != nullptr) {
    PyErr_SetObject(kUtilStatusError, err);
    Py_DECREF(err);
  }  // otherwise error is already set
}

Status StatusFromPyException() {
  if (!PyErr_Occurred()) {
    return OkStatus();
  }

  if (PyErr_ExceptionMatches(PyExc_MemoryError)) {
    return Status(util::error::RESOURCE_EXHAUSTED, PyExcFetch());
  }
  if (PyErr_ExceptionMatches(PyExc_NotImplementedError)) {
    return Status(util::error::UNIMPLEMENTED, PyExcFetch());
  }
  if (PyErr_ExceptionMatches(PyExc_KeyboardInterrupt)) {
    return Status(util::error::ABORTED, PyExcFetch());
  }
  if (PyErr_ExceptionMatches(PyExc_SystemError) ||
      PyErr_ExceptionMatches(PyExc_SyntaxError)) {
    return Status(util::error::INTERNAL, PyExcFetch());
  }
  if (PyErr_ExceptionMatches(PyExc_TypeError)) {
    return Status(util::error::INVALID_ARGUMENT, PyExcFetch());
  }
  if (PyErr_ExceptionMatches(PyExc_ValueError)) {
    return Status(util::error::OUT_OF_RANGE, PyExcFetch());
  }
  if (PyErr_ExceptionMatches(PyExc_LookupError)) {
    return Status(util::error::NOT_FOUND, PyExcFetch());
  }

  return Status(util::error::UNKNOWN, PyExcFetch());
}

PyObject* Clif_PyObjFrom(const Status& c, const clif::py::PostConv& unused) {
  if (!c.ok()) {
    ErrorFromStatus(c);
    return nullptr;
  }
  return Get_UtilStatusOk();
}

std::string PyExcFetch() {
  assert(PyErr_Occurred());  // Must only call PyExcFetch after an exception.
  PyObject* ptype;
  PyObject* pvalue;
  PyObject* ptraceback;
  PyErr_Fetch(&ptype, &pvalue, &ptraceback);
  std::string err = clif::ClassName(ptype);
  if (pvalue) {
    PyObject* str = PyObject_Str(pvalue);
    if (str) {
#if PY_MAJOR_VERSION < 3
      absl::StrAppend(&err, ": ", PyString_AS_STRING(str));
#else
      absl::StrAppend(&err, ": ", PyUnicode_AsUTF8(str));
#endif
      Py_DECREF(str);
    }
    Py_DECREF(pvalue);
  }
  Py_DECREF(ptype);
  Py_XDECREF(ptraceback);
  return err;
}

}  // namespace util
}  // namespace tink
}  // namespace crypto
