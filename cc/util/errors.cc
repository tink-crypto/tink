// Copyright 2017 Google Inc.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE  // needed for vasprintf(3)
#endif

#include "tink/util/errors.h"

#include <stdarg.h>
#include <stdlib.h>

#include "tink/util/status.h"

using crypto::tink::util::error::Code;
using crypto::tink::util::Status;

namespace crypto {
namespace tink {

// Construct a Status object given a printf-style va list.
Status ToStatusF(Code code, const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  char* p;
  if (vasprintf(&p, format, ap) < 0) {
    abort();
  }
  va_end(ap);
  Status status(code, p);
  free(p);
  return status;
}

}  // namespace tink
}  // namespace crypto
