// Copyright 2019 Google LLC
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

#include "tink/core/template_util.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {
class C0 {};
class C1 {};
class C2 {};
class C3 {};
class C4 {};
}  // namespace

static_assert(!HasDuplicates<>::value, "");
static_assert(!HasDuplicates<C0>::value, "");
static_assert(!HasDuplicates<C0, C1>::value, "");
static_assert(!HasDuplicates<C0, C1, C2>::value, "");
static_assert(!HasDuplicates<C0, C1, C2, C3>::value, "");

static_assert(HasDuplicates<C0, C0>::value, "");
static_assert(HasDuplicates<C0, C1, C0>::value, "");
static_assert(HasDuplicates<C0, C1, C1>::value, "");
static_assert(HasDuplicates<C0, C0, C1>::value, "");
static_assert(HasDuplicates<C0, C1, C2, C3, C1, C4>::value, "");

static_assert(IndexOf<C0, List<C0, C1, C2, C3>>::value == 0, "");
static_assert(IndexOf<C1, List<C0, C1, C2, C3>>::value == 1, "");
static_assert(IndexOf<C2, List<C0, C1, C2, C3>>::value == 2, "");
static_assert(IndexOf<C3, List<C0, C1, C2, C3>>::value == 3, "");

static_assert(IndexOf<C0, List<C0, C1, C2, C3, C1>>::value == 0, "");
static_assert(IndexOf<C1, List<C0, C1, C2, C3, C1>>::value == 1, "");
static_assert(IndexOf<C2, List<C0, C1, C2, C3, C1>>::value == 2, "");
static_assert(IndexOf<C3, List<C0, C1, C2, C3, C1>>::value == 3, "");

}  // namespace internal
}  // namespace tink
}  // namespace crypto
