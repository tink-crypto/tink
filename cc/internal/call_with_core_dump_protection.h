// Copyright 2023 Google LLC
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

#ifndef TINK_INTERNAL_CALL_WITH_CORE_DUMP_PROTECTION_H_
#define TINK_INTERNAL_CALL_WITH_CORE_DUMP_PROTECTION_H_

#include <type_traits>

namespace crypto {
namespace tink {
namespace internal {

// Just a stub.
// Internally we have great control over core dump collection and use this
// function to redact execution state (e.g. CPU register values) of sensitive
// crypto operations.
// If you are interested in implementing it for your platform, open a GitHub
// issue.
template <typename Func>
typename std::invoke_result_t<Func> CallWithCoreDumpProtection(Func&& func) {
  return func();
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_CALL_WITH_CORE_DUMP_PROTECTION_H_
