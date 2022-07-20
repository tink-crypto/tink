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

#include "tink/aead/internal/zero_copy_aead_wrapper.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "tink/crypto_format.h"
#include "tink/subtle/subtle_util.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

typedef crypto::tink::PrimitiveSet<ZeroCopyAead>::Entry<ZeroCopyAead>
    ZeroCopyAeadEntry;

util::Status Validate(PrimitiveSet<ZeroCopyAead>* aead_set) {
  if (aead_set == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "aead_set must be non-NULL");
  }
  if (aead_set->get_primary() == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "aead_set has no primary");
  }
  return util::OkStatus();
}

class ZeroCopyAeadSetWrapper : public Aead {
 public:
  explicit ZeroCopyAeadSetWrapper(
      std::unique_ptr<PrimitiveSet<ZeroCopyAead>> aead_set)
      : aead_set_(std::move(aead_set)) {}

  util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view associated_data) const override;

  util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view associated_data) const override;

  ~ZeroCopyAeadSetWrapper() override {}

 private:
  std::unique_ptr<PrimitiveSet<ZeroCopyAead>> aead_set_;
};

util::StatusOr<std::string> ZeroCopyAeadSetWrapper::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data) const {
  std::string ciphertext = aead_set_->get_primary()->get_identifier();
  int64_t key_id_size = ciphertext.size();
  ZeroCopyAead& aead = aead_set_->get_primary()->get_primitive();
  subtle::ResizeStringUninitialized(
      &ciphertext, key_id_size + aead.MaxEncryptionSize(plaintext.size()));

  // Write ciphertext at position ciphertext + CryptoFormat::kNonRawPrefixSize.
  util::StatusOr<int64_t> ciphertext_size =
      aead.Encrypt(plaintext, associated_data,
                   absl::MakeSpan(ciphertext).subspan(key_id_size));
  if (!ciphertext_size.ok()) return ciphertext_size.status();
  ciphertext.resize(key_id_size + *ciphertext_size);

  return ciphertext;
}

util::StatusOr<std::string> ZeroCopyAeadSetWrapper::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data) const {
  if (ciphertext.size() > CryptoFormat::kNonRawPrefixSize) {
    std::string key_id =
        std::string(ciphertext.substr(0, CryptoFormat::kNonRawPrefixSize));
    util::StatusOr<const std::vector<std::unique_ptr<ZeroCopyAeadEntry>>*>
        primitives = aead_set_->get_primitives(key_id);

    if (primitives.ok() && *primitives != nullptr) {
      absl::string_view raw_ciphertext =
          ciphertext.substr(key_id.size(), ciphertext.size());

      for (const std::unique_ptr<ZeroCopyAeadEntry>& entry : **primitives) {
        ZeroCopyAead& aead = entry->get_primitive();
        std::string plaintext;
        subtle::ResizeStringUninitialized(
            &plaintext, aead.MaxDecryptionSize(raw_ciphertext.size()));
        util::StatusOr<int64_t> plaintext_size = entry->get_primitive().Decrypt(
            raw_ciphertext, associated_data, absl::MakeSpan(plaintext));
        if (plaintext_size.ok()) {
          plaintext.resize(*plaintext_size);
          return plaintext;
        }
      }
    }
  }

  // Try raw keys because matching keys failed to decrypt.
  util::StatusOr<const std::vector<std::unique_ptr<ZeroCopyAeadEntry>>*>
      raw_primitives = aead_set_->get_raw_primitives();
  if (raw_primitives.ok() && *raw_primitives != nullptr) {
    for (const std::unique_ptr<ZeroCopyAeadEntry>& entry : **raw_primitives) {
      ZeroCopyAead& aead = entry->get_primitive();
      std::string plaintext;
      subtle::ResizeStringUninitialized(
          &plaintext, aead.MaxDecryptionSize(ciphertext.size()));
      util::StatusOr<int64_t> plaintext_size =
          aead.Decrypt(ciphertext, associated_data, absl::MakeSpan(plaintext));
      if (plaintext_size.ok()) {
        plaintext.resize(*plaintext_size);
        return plaintext;
      }
    }
  }

  return util::Status(absl::StatusCode::kInvalidArgument, "Decryption failed");
}

}  // anonymous namespace

util::StatusOr<std::unique_ptr<Aead>> ZeroCopyAeadWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<ZeroCopyAead>> aead_set) const {
  util::Status status = Validate(aead_set.get());
  if (!status.ok()) return status;
  std::unique_ptr<Aead> aead =
      absl::make_unique<ZeroCopyAeadSetWrapper>(std::move(aead_set));
  return std::move(aead);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
