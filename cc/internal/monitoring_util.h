// Copyright 2022 Google LLC
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
#ifndef TINK_INTERNAL_MONITORING_UTIL_H_
#define TINK_INTERNAL_MONITORING_UTIL_H_

#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/strip.h"
#include "tink/internal/key_status_util.h"
#include "tink/key_status.h"
#include "tink/monitoring/monitoring.h"
#include "tink/primitive_set.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

constexpr char kKeyTypePrefix[] = "type.googleapis.com/google.crypto.";

// Constructs a MonitoringKeySetInfo object from a PrimitiveSet `primitive_set`
// for a given primitive P.
template <class P>
crypto::tink::util::StatusOr<MonitoringKeySetInfo>
MonitoringKeySetInfoFromPrimitiveSet(const PrimitiveSet<P>& primitive_set) {
  const std::vector<typename PrimitiveSet<P>::template Entry<P>*>
      primitive_set_entries = primitive_set.get_all();
  if (primitive_set_entries.empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "The primitive set is empty");
  }
  if (primitive_set.get_primary() == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "The primary keys must not be null");
  }
  std::vector<MonitoringKeySetInfo::Entry> keyset_info_entries = {};
  for (const auto& entry : primitive_set_entries) {
    util::StatusOr<KeyStatus> key_status =
        FromKeyStatusType(entry->get_status());
    if (!key_status.ok()) return key_status.status();

    auto keyset_info_entry = MonitoringKeySetInfo::Entry(
        *key_status, entry->get_key_id(),
        absl::StripPrefix(entry->get_key_type_url(), kKeyTypePrefix),
        OutputPrefixType_Name(entry->get_output_prefix_type()));
    keyset_info_entries.push_back(keyset_info_entry);
  }
  MonitoringKeySetInfo keyset_info(primitive_set.get_annotations(),
                                   keyset_info_entries,
                                   primitive_set.get_primary()->get_key_id());
  return keyset_info;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_MONITORING_UTIL_H_
