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
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_KEYDERIVATION_INTERNAL_PRF_BASED_DERIVER_H_
#define TINK_KEYDERIVATION_INTERNAL_PRF_BASED_DERIVER_H_

#include <memory>
#include <utility>

#include "tink/keyderivation/keyset_deriver.h"
#include "tink/keyset_handle.h"
#include "tink/subtle/prf/streaming_prf.h"

namespace crypto {
namespace tink {
namespace internal {

// The PrfBasedDeriver first uses a PRF to get some randomness, then gives this
// to the Tink registry to derive a key.
class PrfBasedDeriver : public KeysetDeriver {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<KeysetDeriver>> New(
      const ::google::crypto::tink::KeyData& prf_key,
      const ::google::crypto::tink::KeyTemplate& key_template);

  crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>> DeriveKeyset(
      absl::string_view salt) const override;

 private:
  PrfBasedDeriver(std::unique_ptr<StreamingPrf> streaming_prf,
                  const ::google::crypto::tink::KeyTemplate& key_template)
      : streaming_prf_(std::move(streaming_prf)), key_template_(key_template) {}

  const ::std::unique_ptr<StreamingPrf> streaming_prf_;
  const ::google::crypto::tink::KeyTemplate key_template_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYDERIVATION_INTERNAL_PRF_BASED_DERIVER_H_
