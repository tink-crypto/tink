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

#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/strings/string_view.h"
#include "tink/subtle/wycheproof_util.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::subtle::WycheproofUtil;

std::vector<WycheproofTestVector> ReadWycheproofTestVectors(
    absl::string_view file_name, int allowed_tag_size, int allowed_iv_size,
    absl::flat_hash_set<int> allowed_key_sizes) {
  std::unique_ptr<rapidjson::Document> root =
      WycheproofUtil::ReadTestVectors(std::string(file_name));

  std::vector<WycheproofTestVector> test_vectors;

  for (const rapidjson::Value& test_group : (*root)["testGroups"].GetArray()) {
    const int iv_size = test_group["ivSize"].GetInt();
    const int key_size = test_group["keySize"].GetInt();
    const int tag_size = test_group["tagSize"].GetInt();
    if (!allowed_key_sizes.contains(key_size) || iv_size != allowed_iv_size ||
        tag_size != allowed_tag_size) {
      continue;
    }
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
