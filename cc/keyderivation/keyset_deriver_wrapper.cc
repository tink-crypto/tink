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

#include "tink/keyderivation/keyset_deriver_wrapper.h"

#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/keyderivation/internal/keyset_deriver_set_wrapper_impl.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

namespace {

using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;

util::Status Validate(PrimitiveSet<KeysetDeriver>* deriver_set) {
  if (deriver_set == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "deriver_set must be non-NULL");
  }
  if (deriver_set->get_primary() == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "deriver_set has no primary");
  }
  return util::OkStatus();
}

class KeysetDeriverSetWrapper : public KeysetDeriver {
 public:
  explicit KeysetDeriverSetWrapper(
      std::unique_ptr<PrimitiveSet<KeysetDeriver>> deriver_set)
      : deriver_set_(std::move(deriver_set)) {}

  crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>> DeriveKeyset(
      absl::string_view salt) const override;

  ~KeysetDeriverSetWrapper() override = default;

 private:
  std::unique_ptr<PrimitiveSet<KeysetDeriver>> deriver_set_;
};

crypto::tink::util::StatusOr<KeyData> DeriveAndGetKeyData(
    absl::string_view salt, const KeysetDeriver& deriver) {
  auto keyset_handle_or = deriver.DeriveKeyset(salt);
  if (!keyset_handle_or.ok()) return keyset_handle_or.status();
  const Keyset& keyset =
      CleartextKeysetHandle::GetKeyset(*keyset_handle_or.value());
  if (keyset.key_size() != 1) {
    return util::Status(
        absl::StatusCode::kInternal,
        "Wrapper Deriver must create a keyset with exactly one KeyData");
  }
  return keyset.key(0).key_data();
}

crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>>
KeysetDeriverSetWrapper::DeriveKeyset(absl::string_view salt) const {
  Keyset keyset;
  for (const auto* entry :
       internal::KeysetDeriverSetWrapperImpl::get_all_in_keyset_order(
           *deriver_set_)) {
    Keyset::Key* key = keyset.add_key();

    crypto::tink::util::StatusOr<KeyData> key_data_or =
        DeriveAndGetKeyData(salt, entry->get_primitive());
    if (!key_data_or.ok()) return key_data_or.status();
    *key->mutable_key_data() = key_data_or.value();
    key->set_status(entry->get_status());
    key->set_output_prefix_type(entry->get_output_prefix_type());
    key->set_key_id(entry->get_key_id());
  }
  keyset.set_primary_key_id(deriver_set_->get_primary()->get_key_id());
  return CleartextKeysetHandle::GetKeysetHandle(keyset);
}

}  // namespace

crypto::tink::util::StatusOr<std::unique_ptr<KeysetDeriver>>
KeysetDeriverWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<KeysetDeriver>> deriver_set) const {
  util::Status status = Validate(deriver_set.get());
  if (!status.ok()) return status;
  return {absl::make_unique<KeysetDeriverSetWrapper>(std::move(deriver_set))};
}

}  // namespace tink
}  // namespace crypto
