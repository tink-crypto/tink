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
#include "tink/aead/internal/wycheproof_aead.h"

#include <memory>
#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/subtle/wycheproof_util.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::subtle::WycheproofUtil;

std::vector<WycheproofTestVector> ReadWycheproofTestVectors(
    absl::string_view file_name) {
  std::unique_ptr<rapidjson::Document> root =
      WycheproofUtil::ReadTestVectors(std::string(file_name));
  std::vector<WycheproofTestVector> test_vectors;
  for (const rapidjson::Value& test_group : (*root)["testGroups"].GetArray()) {
    for (const rapidjson::Value& test : test_group["tests"].GetArray()) {
      test_vectors.push_back(WycheproofTestVector{
          test["comment"].GetString(),
          WycheproofUtil::GetBytes(test["key"]),
          WycheproofUtil::GetBytes(test["iv"]),
          WycheproofUtil::GetBytes(test["msg"]),
          WycheproofUtil::GetBytes(test["ct"]),
          WycheproofUtil::GetBytes(test["aad"]),
          WycheproofUtil::GetBytes(test["tag"]),
          absl::StrCat(test["tcId"].GetInt()),
          test["result"].GetString(),
      });
    }
  }
  return test_vectors;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
