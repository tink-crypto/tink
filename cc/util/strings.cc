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

#include "cc/util/strings.h"

#include <algorithm>
#include <cctype>
#include <string>

namespace crypto {
namespace tink {

std::string to_lowercase(const std::string& s) {
  std::string lowercase(s);
  std::transform(s.begin(), s.end(), lowercase.begin(),
                 [](unsigned char c){ return std::tolower(c); });
  return lowercase;
}
}  // namespace tink
}  // namespace crypto
