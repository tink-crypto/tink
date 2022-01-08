// Copyright 2021 Google LLC
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
#include "tink/internal/err_util.h"

#include "openssl/err.h"

namespace crypto {
namespace tink {
namespace internal {

std::string GetSslErrors() {
  std::string ret;
  ERR_print_errors_cb(
      [](const char *str, size_t len, void *ctx) -> int {
        static_cast<std::string *>(ctx)->append(str, len);
        return 1;
      },
      &ret);
  return ret;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
