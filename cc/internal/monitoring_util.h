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
#include "tink/monitoring/monitoring.h"
#include "tink/primitive_set.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

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
    MonitoringKeySetInfo::Entry::KeyStatus key_status;
    switch (entry->get_status()) {
      case google::crypto::tink::KeyStatusType::ENABLED: {
        key_status = MonitoringKeySetInfo::Entry::KeyStatus::kEnabled;
        break;
      }
      case google::crypto::tink::KeyStatusType::DISABLED: {
        key_status = MonitoringKeySetInfo::Entry::KeyStatus::kDisabled;
        break;
      }
      case google::crypto::tink::KeyStatusType::DESTROYED: {
        key_status = MonitoringKeySetInfo::Entry::KeyStatus::kDestroyed;
        break;
      }
      default:
        return util::Status(
            absl::StatusCode::kInvalidArgument,
            absl::StrCat("Unknown key status ", entry->get_status()));
    }

    // TODO(b/222245356): Populate key_format_as_string with the actual key
    // format when available. For now, we use the key type URL.
    auto keyset_info_entry = MonitoringKeySetInfo::Entry(
        key_status, entry->get_key_id(), entry->get_key_type_url());
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
