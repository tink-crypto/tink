// Copyright 2022 Google LLC
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
#ifndef TINK_PRF_FAILING_PRFSET_H_
#define TINK_PRF_FAILING_PRFSET_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "tink/prf/prf_set.h"

namespace crypto {
namespace tink {

// Returns a Prf that always returns an error when calling Compute.
// The error message will contain `message`.
std::unique_ptr<Prf> CreateAlwaysFailingPrf(std::string message = "");

// Returns a PrfSet that always returns an error when calling ComputePrimary and
// a set of always failing Prfs when calling GetPrfs().
// The error message will contain `message`.
std::unique_ptr<PrfSet> CreateAlwaysFailingPrfSet(std::string message = "");

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRF_FAILING_PRFSET_H_
