// Copyright 2020 Google LLC
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

#include "tink/subtle/prf/streaming_prf_wrapper.h"

#include "absl/strings/str_cat.h"
#include "tink/subtle/prf/streaming_prf.h"

namespace crypto {
namespace tink {

class StreamingPrfSetWrapper : public StreamingPrf {
 public:
  explicit StreamingPrfSetWrapper(
      std::unique_ptr<PrimitiveSet<StreamingPrf>> streaming_prf_set)
      : streaming_prf_set_(std::move(streaming_prf_set)) {}

  std::unique_ptr<InputStream> ComputePrf(
      absl::string_view input) const override {
    return streaming_prf_set_->get_primary()->get_primitive().ComputePrf(input);
  }

  ~StreamingPrfSetWrapper() override {}

 private:
  std::unique_ptr<PrimitiveSet<StreamingPrf>> streaming_prf_set_;
};

::crypto::tink::util::StatusOr<std::unique_ptr<StreamingPrf>>
StreamingPrfWrapper::Wrap(std::unique_ptr<PrimitiveSet<StreamingPrf>>
                              streaming_prf_set) const  {
  if (!streaming_prf_set) {
    return crypto::tink::util::Status(
        crypto::tink::util::error::INVALID_ARGUMENT,
        "Passed in streaming_prf_set must be non-NULL");
  }

  auto entries = streaming_prf_set->get_all();

  if (entries.size() != 1) {
    return crypto::tink::util::Status(
        crypto::tink::util::error::INVALID_ARGUMENT,
        absl::StrCat("StreamingPrfWrapper can only create StreamingPrf objects "
                     "from keysets "
                     "with exactly one key, but the but the given set has ",
                     entries.size(), " keys."));
  }
  auto* entry = entries[0];
  if (entry->get_status() != google::crypto::tink::KeyStatusType::ENABLED) {
    return crypto::tink::util::Status(
        crypto::tink::util::error::INVALID_ARGUMENT,
        absl::StrCat("StreamingPrfWrapper can only create StreamingPrf objects "
                     "from keysets "
                     "with an enabled keys, but the key is ",
                     entry->get_status()));
  }
  if (entry->get_output_prefix_type() !=
      google::crypto::tink::OutputPrefixType::RAW) {
    return crypto::tink::util::Status(
        crypto::tink::util::error::INVALID_ARGUMENT,
        absl::StrCat("StreamingPrfWrapper can only create StreamingPrf objects "
                     "from keysets with a single enabled key with "
                     "OutputPrefixType::RAW, "
                     "but output_prefix_type is ",
                     entry->get_output_prefix_type()));
  }
  return {
      absl::make_unique<StreamingPrfSetWrapper>(std::move(streaming_prf_set))};
}

}  // namespace tink
}  // namespace crypto
