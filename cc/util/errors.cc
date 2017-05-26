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

#include "cc/util/errors.h"

#include <stdarg.h>
#include <stdlib.h>

#include "cc/util/status.h"

using util::error::Code;
using util::Status;

namespace crypto {
namespace tink {

// Construct a Status object given a printf-style va list.
Status ToStatusF(Code code, const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  char* p;
  vasprintf(&p, format, ap);
  va_end(ap);
  Status status(code, p);
  free(p);
  return status;
}

}  // namespace tink
}  // namespace crypto
