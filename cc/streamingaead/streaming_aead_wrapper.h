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

#ifndef TINK_STREAMINGAEAD_STREAMING_AEAD_WRAPPER_H_
#define TINK_STREAMINGAEAD_STREAMING_AEAD_WRAPPER_H_

#include "absl/strings/string_view.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/streaming_aead.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// Wraps a set of StreamingAead-instances that correspond to a keyset,
// and combines them into a single StreamingAead-primitive, that uses
// the provided instances, depending on the context:
//   * StreamingAead::NewEncryptingStream(...) uses the primary instance
//     from the set
//   * StreamingAead::NewDecryptingStream(...) uses the instance that matches
//     the ciphertext prefix.
class StreamingAeadWrapper
    : public PrimitiveWrapper<StreamingAead, StreamingAead> {
 public:
  // Returns a StreamingAead-primitive that uses StreamingAead-instances
  // provided in 'streaming_aead_set', which must be non-NULL and must contain
  // a primary instance.
  util::StatusOr<std::unique_ptr<StreamingAead>> Wrap(
      std::unique_ptr<PrimitiveSet<StreamingAead>> streaming_aead_set)
      const override;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMINGAEAD_STREAMING_AEAD_WRAPPER_H_
