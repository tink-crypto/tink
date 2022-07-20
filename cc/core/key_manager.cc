// Copyright 2018 Google Inc.
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
#include "tink/key_manager.h"

#include <memory>

#include "absl/memory/memory.h"

namespace crypto {
namespace tink {

// A key factory which always fails.
class AlwaysFailingKeyFactory : public KeyFactory {
 public:
  AlwaysFailingKeyFactory() = delete;
  explicit AlwaysFailingKeyFactory(const crypto::tink::util::Status& status)
      : status_(status) {}

  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(const portable_proto::MessageLite& key_format) const override {
    return status_;
  }

  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(absl::string_view serialized_key_format) const override {
    return status_;
  }

  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(absl::string_view serialized_key_format) const override {
    return status_;
  }

 private:
  crypto::tink::util::Status status_;
};
std::unique_ptr<KeyFactory> KeyFactory::AlwaysFailingFactory(
    const crypto::tink::util::Status& status) {
  return absl::make_unique<AlwaysFailingKeyFactory>(status);
}
}  // namespace tink
}  // namespace crypto
