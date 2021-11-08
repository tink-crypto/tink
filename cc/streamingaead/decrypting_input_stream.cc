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

#include "tink/streamingaead/decrypting_input_stream.h"

#include <algorithm>
#include <cstring>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/input_stream.h"
#include "tink/primitive_set.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/buffered_input_stream.h"
#include "tink/streamingaead/shared_input_stream.h"
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
StatusOr<std::unique_ptr<InputStream>> DecryptingInputStream::New(
    std::shared_ptr<PrimitiveSet<StreamingAead>> primitives,
    std::unique_ptr<crypto::tink::InputStream> ciphertext_source,
    absl::string_view associated_data) {
  std::unique_ptr<DecryptingInputStream> dec_stream(
      new DecryptingInputStream());
  dec_stream->primitives_ = primitives;
  dec_stream->buffered_ct_source_ =
      std::make_shared<BufferedInputStream>(std::move(ciphertext_source));
  dec_stream->associated_data_ = std::string(associated_data);
  dec_stream->attempted_matching_ = false;
  dec_stream->matching_stream_ = nullptr;
  return {std::move(dec_stream)};
}

util::StatusOr<int> DecryptingInputStream::Next(const void** data) {
  if (matching_stream_ != nullptr) {
    return matching_stream_->Next(data);
  }
  if (attempted_matching_) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Could not find a decrypter matching the ciphertext stream.");
  }
  // Matching has not been attempted yet, so try it now.
  attempted_matching_ = true;
  auto raw_primitives_result = primitives_->get_raw_primitives();
  if (!raw_primitives_result.ok()) {
    return Status(absl::StatusCode::kInternal, "No RAW primitives found");
  }
  for (auto& primitive : *(raw_primitives_result.ValueOrDie())) {
    StreamingAead& streaming_aead = primitive->get_primitive();
    auto shared_ct = absl::make_unique<SharedInputStream>(
        buffered_ct_source_.get());
    auto decrypting_stream_result = streaming_aead.NewDecryptingStream(
        std::move(shared_ct), associated_data_);
    if (decrypting_stream_result.ok()) {
      auto next_result = decrypting_stream_result.ValueOrDie()->Next(data);
      if (next_result.status().code() == absl::StatusCode::kOutOfRange ||
          next_result.ok()) {  // Found a match.
        buffered_ct_source_->DisableRewinding();
        matching_stream_ = std::move(decrypting_stream_result.ValueOrDie());
        return next_result;
      }
    }
    // Not a match, rewind and try the next primitive.
    Status s = buffered_ct_source_->Rewind();
    if (!s.ok()) {
      return s;
    }
  }
  return Status(absl::StatusCode::kInvalidArgument,
                "Could not find a decrypter matching the ciphertext stream.");
}

void DecryptingInputStream::BackUp(int count) {
  if (matching_stream_ != nullptr) {
    matching_stream_->BackUp(count);
  }
}


int64_t DecryptingInputStream::Position() const {
  if (matching_stream_ != nullptr) {
    return matching_stream_->Position();
  }
  return 0;
}

}  // namespace streamingaead
}  // namespace tink
}  // namespace crypto
