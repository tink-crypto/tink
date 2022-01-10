// Copyright 2019 Google Inc.
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

#include "tink/streamingaead/decrypting_random_access_stream.h"

#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "tink/primitive_set.h"
#include "tink/random_access_stream.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/shared_random_access_stream.h"
#include "tink/util/buffer.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace streamingaead {

using crypto::tink::PrimitiveSet;
using crypto::tink::StreamingAead;
using util::Status;
using util::StatusOr;

// static
StatusOr<std::unique_ptr<RandomAccessStream>> DecryptingRandomAccessStream::New(
    std::shared_ptr<PrimitiveSet<StreamingAead>> primitives,
    std::unique_ptr<crypto::tink::RandomAccessStream> ciphertext_source,
    absl::string_view associated_data) {
  if (primitives == nullptr) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "primitives must be non-null.");
  }
  if (ciphertext_source == nullptr) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "ciphertext_source must be non-null.");
  }
  return {absl::WrapUnique(new DecryptingRandomAccessStream(
      primitives, std::move(ciphertext_source), associated_data))};
}

util::Status DecryptingRandomAccessStream::PRead(
    int64_t position, int count,
    crypto::tink::util::Buffer* dest_buffer) {
  {  // "fast-track": quickly proceed if matching has been attempted/found.
    if (dest_buffer == nullptr) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "dest_buffer must be non-null");
    }
    if (count < 0) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "count cannot be negative");
    }
    if (count > dest_buffer->allocated_size()) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "buffer too small");
    }
    if (position < 0) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "position cannot be negative");
    }
    absl::ReaderMutexLock lock(&matching_mutex_);
    if (matching_stream_ != nullptr) {
      return matching_stream_->PRead(position, count, dest_buffer);
    }
    if (attempted_matching_) {
      return Status(absl::StatusCode::kInvalidArgument,
                    "Did not find a decrypter matching the ciphertext stream.");
    }
  }
  // Matching has not been attempted yet, so try it now.
  absl::MutexLock lock(&matching_mutex_);

  // Re-check that matching hasn't been attempted in the meantime.
  if (matching_stream_ != nullptr) {
    return matching_stream_->PRead(position, count, dest_buffer);
  }
  if (attempted_matching_) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Did not find a decrypter matching the ciphertext stream.");
  }
  attempted_matching_ = true;
  auto raw_primitives_result = primitives_->get_raw_primitives();
  if (!raw_primitives_result.ok()) {
    return Status(absl::StatusCode::kInternal, "No RAW primitives found");
  }
  for (auto& primitive : *(raw_primitives_result.ValueOrDie())) {
    StreamingAead& streaming_aead = primitive->get_primitive();
    auto shared_ct = absl::make_unique<SharedRandomAccessStream>(
        ciphertext_source_.get());
    auto decrypting_stream_result =
        streaming_aead.NewDecryptingRandomAccessStream(
            std::move(shared_ct), associated_data_);
    if (decrypting_stream_result.ok()) {
      auto status = decrypting_stream_result.ValueOrDie()->PRead(
          position, count, dest_buffer);
      if (status.ok() || status.code() == absl::StatusCode::kOutOfRange) {
        // Found a match.
        matching_stream_ = std::move(decrypting_stream_result.ValueOrDie());
        return status;
      }
    }
    // Not a match, try the next primitive.
  }
  return Status(absl::StatusCode::kInvalidArgument,
                "Could not find a decrypter matching the ciphertext stream.");
}

StatusOr<int64_t> DecryptingRandomAccessStream::size() {
  absl::ReaderMutexLock lock(&matching_mutex_);
  if (matching_stream_ != nullptr) {
    return matching_stream_->size();
  }
  // TODO(b/139722894): attempt matching here?
  return Status(absl::StatusCode::kUnavailable, "no matching found yet");
}

}  // namespace streamingaead
}  // namespace tink
}  // namespace crypto
