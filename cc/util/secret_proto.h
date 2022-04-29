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

#ifndef TINK_UTIL_SECRET_PROTO_H_
#define TINK_UTIL_SECRET_PROTO_H_

#include <memory>
#include <utility>

#include "google/protobuf/arena.h"
#include "absl/memory/memory.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace util {

namespace internal {

inline google::protobuf::ArenaOptions SecretArenaOptions() {
  google::protobuf::ArenaOptions options;
  options.block_alloc = [](size_t sz) {
    return SanitizingAllocator<void>().allocate(sz);
  };
  options.block_dealloc = [](void* ptr, size_t sz) {
    return SanitizingAllocator<void>().deallocate(ptr, sz);
  };
  return options;
}

}  // namespace internal

// Stores secret (sensitive) protobuf and makes sure it's marked as such and
// destroyed in a safe way.
//
// Note: Currently does not protect fields of type "string" and "bytes"
// (depends on https://github.com/protocolbuffers/protobuf/issues/1896)
template <typename T>
class SecretProto {
 public:
  static StatusOr<SecretProto<T>> ParseFromSecretData(const SecretData& data) {
    SecretProto<T> proto;
    if (!proto->ParseFromArray(data.data(), data.size())) {
      return Status(absl::StatusCode::kInternal, "Could not parse proto");
    }
    return proto;
  }

  SecretProto() {}

  SecretProto(const SecretProto& other) { *value_ = *other.value_; }

  SecretProto(SecretProto&& other) { *this = std::move(other); }

  explicit SecretProto(const T& value) { *value_ = value; }

  SecretProto& operator=(const SecretProto& other) {
    *value_ = *other.value_;
    return *this;
  }

  SecretProto& operator=(SecretProto&& other) {
    using std::swap;
    swap(arena_, other.arena_);
    swap(value_, other.value_);
    return *this;
  }

  inline T* get() { return value_; }

  // Accessors to the underlying message.
  inline T* operator->() { return value_; }
  inline const T* operator->() const { return value_; }

  inline T& operator*() { return *value_; }
  inline const T& operator*() const { return *value_; }

  StatusOr<SecretData> SerializeAsSecretData() const {
    SecretData data(value_->ByteSizeLong());
    if (!value_->SerializeToArray(data.data(), data.size())) {
      return Status(absl::StatusCode::kInternal, "Could not serialize proto");
    }
    return data;
  }

 private:
  std::unique_ptr<google::protobuf::Arena> arena_ =
      absl::make_unique<google::protobuf::Arena>(internal::SecretArenaOptions());
  T* value_ = google::protobuf::Arena::CreateMessage<T>(arena_.get());
};

}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_SECRET_PROTO_H_
