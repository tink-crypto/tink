// Copyright 2017 Google Inc.
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

#ifndef TINK_PRIMITIVE_SET_H_
#define TINK_PRIMITIVE_SET_H_

#include <algorithm>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "tink/crypto_format.h"
#include "tink/util/errors.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// A container class for a set of primitives (i.e. implementations of
// cryptographic primitives offered by Tink).  It provides also
// additional properties for the primitives it holds.  In particular,
// one of the primitives in the set can be distinguished as "the
// primary" one.
//
// PrimitiveSet is an auxiliary class used for supporting key rotation:
// primitives in a set correspond to keys in a keyset.  Users will
// usually work with primitive instances, which essentially wrap
// primitive sets.  For example an instance of an Aead-primitive for a
// given keyset holds a set of Aead-primitivies corresponding to the
// keys in the keyset, and uses the set members to do the actual
// crypto operations: to encrypt data the primary Aead-primitive from
// the set is used, and upon decryption the ciphertext's prefix
// determines the identifier of the primitive from the set.
//
// PrimitiveSet is a public class to allow its use in implementations
// of custom primitives.
template <class P>
class PrimitiveSet {
 public:
  // Entry-objects hold individual instances of primitives in the set.
  template <class P2>
  class Entry {
   public:
    static crypto::tink::util::StatusOr<std::unique_ptr<Entry<P>>> New(
        std::unique_ptr<P> primitive,
        const google::crypto::tink::KeysetInfo::KeyInfo& key_info) {
      if (key_info.status() != google::crypto::tink::KeyStatusType::ENABLED) {
        return util::Status(absl::StatusCode::kInvalidArgument,
                            "The key must be ENABLED.");
      }
      auto identifier_result = CryptoFormat::GetOutputPrefix(key_info);
      if (!identifier_result.ok()) return identifier_result.status();
      if (primitive == nullptr) {
        return util::Status(absl::StatusCode::kInvalidArgument,
                            "The primitive must be non-null.");
      }
      std::string identifier = identifier_result.value();
      return absl::WrapUnique(new Entry(std::move(primitive), identifier,
                                        key_info.status(), key_info.key_id(),
                                        key_info.output_prefix_type(),
                                        key_info.type_url()));
    }

    P2& get_primitive() const { return *primitive_; }

    const std::string& get_identifier() const { return identifier_; }

    google::crypto::tink::KeyStatusType get_status() const { return status_; }

    uint32_t get_key_id() const { return key_id_; }

    google::crypto::tink::OutputPrefixType get_output_prefix_type() const {
      return output_prefix_type_;
    }

    absl::string_view get_key_type_url() const { return key_type_url_; }

   private:
    Entry(std::unique_ptr<P2> primitive, const std::string& identifier,
          google::crypto::tink::KeyStatusType status, uint32_t key_id,
          google::crypto::tink::OutputPrefixType output_prefix_type,
          absl::string_view key_type_url)
        : primitive_(std::move(primitive)),
          identifier_(identifier),
          status_(status),
          key_id_(key_id),
          output_prefix_type_(output_prefix_type),
          key_type_url_(key_type_url) {}

    std::unique_ptr<P> primitive_;
    std::string identifier_;
    google::crypto::tink::KeyStatusType status_;
    uint32_t key_id_;
    google::crypto::tink::OutputPrefixType output_prefix_type_;
    const std::string key_type_url_;
  };

  typedef std::vector<std::unique_ptr<Entry<P>>> Primitives;
  typedef std::unordered_map<std::string, Primitives>
      CiphertextPrefixToPrimitivesMap;

 private:
  // Helper methods for mutations, used by the Builder and the deprecated
  // mutation methods on PrimitiveSet.

  static crypto::tink::util::Status SetPrimaryImpl(
      Entry<P>** output, Entry<P>* primary,
      const CiphertextPrefixToPrimitivesMap& primitives) {
    if (!primary) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "The primary primitive must be non-null.");
    }
    if (primary->get_status() != google::crypto::tink::KeyStatusType::ENABLED) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Primary has to be enabled.");
    }

    if (primitives.count(primary->get_identifier()) == 0) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Primary cannot be set to an entry which is "
                          "not held by this primitive set.");
    }

    *output = primary;
    return crypto::tink::util::OkStatus();
  }

  static crypto::tink::util::StatusOr<Entry<P>*> AddPrimitiveImpl(
      std::unique_ptr<P> primitive,
      const google::crypto::tink::KeysetInfo::KeyInfo& key_info,
      CiphertextPrefixToPrimitivesMap& primitives) {
    auto entry_or = Entry<P>::New(std::move(primitive), key_info);
    if (!entry_or.ok()) return entry_or.status();

    std::string identifier = entry_or.value()->get_identifier();
    primitives[identifier].push_back(std::move(entry_or.value()));
    return primitives[identifier].back().get();
  }

 public:
  // Builder is used to construct PrimitiveSet objects. Objects returned by the
  // builder are immutable. Calling any of the non-const methods on them will
  // fail.
  class Builder {
   public:
    // Adds 'primitive' to this set for the specified 'key'.
    Builder& AddPrimitive(
        std::unique_ptr<P> primitive,
        const google::crypto::tink::KeysetInfo::KeyInfo& key_info) & {
      absl::MutexLock lock(&mutex_);
      if (!status_.ok()) return *this;
      status_ = AddPrimitiveImpl(std::move(primitive), key_info, primitives_)
                    .status();
      return *this;
    }

    Builder&& AddPrimitive(
        std::unique_ptr<P> primitive,
        const google::crypto::tink::KeysetInfo::KeyInfo& key_info) && {
      return std::move(AddPrimitive(std::move(primitive), key_info));
    }

    // Adds 'primitive' to this set for the specified 'key' and marks it
    // primary.
    Builder& AddPrimaryPrimitive(
        std::unique_ptr<P> primitive,
        const google::crypto::tink::KeysetInfo::KeyInfo& key_info) & {
      absl::MutexLock lock(&mutex_);
      if (!status_.ok()) return *this;
      auto entry_result =
          AddPrimitiveImpl(std::move(primitive), key_info, primitives_);
      if (!entry_result.ok()) {
        status_ = entry_result.status();
        return *this;
      }
      status_ = SetPrimaryImpl(&primary_, entry_result.value(), primitives_);
      return *this;
    }

    Builder&& AddPrimaryPrimitive(
        std::unique_ptr<P> primitive,
        const google::crypto::tink::KeysetInfo::KeyInfo& key_info) && {
      return std::move(AddPrimaryPrimitive(std::move(primitive), key_info));
    }

    // Add the given annotations. Existing annotations will not be overwritten.
    Builder& AddAnnotations(
        absl::flat_hash_map<std::string, std::string> annotations) & {
      absl::MutexLock lock(&mutex_);
      annotations_.merge(std::move(annotations));
      return *this;
    }

    Builder&& AddAnnotations(
        absl::flat_hash_map<std::string, std::string> annotations) && {
      return std::move(AddAnnotations(std::move(annotations)));
    }

    crypto::tink::util::StatusOr<PrimitiveSet<P>> Build() && {
      absl::MutexLock lock(&mutex_);
      if (!status_.ok()) return status_;
      return PrimitiveSet<P>(std::move(primitives_), primary_,
                             std::move(annotations_));
    }

   private:
    // The Entry<P> object is owned by primitives_
    Entry<P>* primary_ ABSL_GUARDED_BY(mutex_) = nullptr;
    CiphertextPrefixToPrimitivesMap primitives_ ABSL_GUARDED_BY(mutex_);
    absl::flat_hash_map<std::string, std::string> annotations_
        ABSL_GUARDED_BY(mutex_);
    absl::Mutex mutex_;
    crypto::tink::util::Status status_ ABSL_GUARDED_BY(mutex_);
  };

  // PrimitiveSet is movable, but not copyable
  PrimitiveSet(PrimitiveSet&&) = default;
  PrimitiveSet<P>& operator=(PrimitiveSet&&) = default;
  PrimitiveSet(const PrimitiveSet&) = delete;
  PrimitiveSet<P>& operator=(const PrimitiveSet&) = delete;

  // Constructs an empty PrimitiveSet.
  // Note: This is equivalent to PrimitiveSet<P>(/*annotations=*/{}).
  ABSL_DEPRECATED(
      "Constructing PrimitiveSet using constructors is deprecated. Use "
      "PrimitiveSet<>::Builder instead.")
  PrimitiveSet<P>() = default;
  // Constructs an empty PrimitiveSet with `annotations`.
  ABSL_DEPRECATED(
      "Constructing PrimitiveSet using constructors is deprecated. Use "
      "PrimitiveSet<>::Builder instead.")
  explicit PrimitiveSet<P>(
      const absl::flat_hash_map<std::string, std::string>& annotations)
      : annotations_(annotations) {}

  // Adds 'primitive' to this set for the specified 'key'.
  ABSL_DEPRECATED(
      "Mutating PrimitiveSets after construction is deprecated. Use "
      "PrimitiveSet<>::Builder instead.")
  crypto::tink::util::StatusOr<Entry<P>*> AddPrimitive(
      std::unique_ptr<P> primitive,
      const google::crypto::tink::KeysetInfo::KeyInfo& key_info) {
    if (!is_mutable()) {
      return util::Status(absl::StatusCode::kFailedPrecondition,
                          "PrimitiveSet is not mutable.");
    }

    absl::MutexLock lock(primitives_mutex_.get());
    return AddPrimitiveImpl(std::move(primitive), key_info, primitives_);
  }

  // Returns the entries with primitives identifed by 'identifier'.
  crypto::tink::util::StatusOr<const Primitives*> get_primitives(
      absl::string_view identifier) const {
    absl::MutexLockMaybe lock(primitives_mutex_.get());
    auto found = primitives_.find(std::string(identifier));
    if (found == primitives_.end()) {
      return ToStatusF(absl::StatusCode::kNotFound,
                       "No primitives found for identifier '%s'.", identifier);
    }
    return &(found->second);
  }

  // Returns all primitives that use RAW prefix.
  crypto::tink::util::StatusOr<const Primitives*> get_raw_primitives() const {
    return get_primitives(CryptoFormat::kRawPrefix);
  }

  // Sets the given 'primary' as the primary primitive of this set.
  ABSL_DEPRECATED(
      "Mutating PrimitiveSets after construction is deprecated. Use "
      "PrimitiveSet<>::Builder instead.")
  crypto::tink::util::Status set_primary(Entry<P>* primary) {
    if (!is_mutable()) {
      return util::Status(absl::StatusCode::kFailedPrecondition,
                          "PrimitiveSet is not mutable.");
    }
    absl::MutexLock lock(primitives_mutex_.get());
    return SetPrimaryImpl(&primary_, primary, primitives_);
  }

  // Returns the entry with the primary primitive.
  const Entry<P>* get_primary() const {
    absl::MutexLockMaybe lock(primitives_mutex_.get());
    return primary_;
  }

  // Returns all entries currently in this primitive set.
  std::vector<Entry<P>*> get_all() const {
    absl::MutexLockMaybe lock(primitives_mutex_.get());
    std::vector<Entry<P>*> result;
    for (const auto& prefix_and_vector : primitives_) {
      for (const auto& primitive : prefix_and_vector.second) {
        result.push_back(primitive.get());
      }
    }
    return result;
  }

  const absl::flat_hash_map<std::string, std::string>& get_annotations() const {
    return annotations_;
  }

  bool is_mutable() const { return primitives_mutex_ != nullptr; }

 private:
  // Constructs an empty PrimitiveSet.
  // Note: This is equivalent to PrimitiveSet<P>(/*annotations=*/{}).
  PrimitiveSet(CiphertextPrefixToPrimitivesMap primitives, Entry<P>* primary,
               absl::flat_hash_map<std::string, std::string> annotations)
      : primary_(primary),
        primitives_mutex_(nullptr),
        primitives_(std::move(primitives)),
        annotations_(std::move(annotations)) {}

  // The Entry<P> object is owned by primitives_
  Entry<P>* primary_ ABSL_GUARDED_BY(primitives_mutex_) = nullptr;
  // If not nullptr, this mutex is used to guard all read and write access to
  // the primitiveset. If nullptr, the primitiveset is immutable (and lockfree).
  mutable std::unique_ptr<absl::Mutex> primitives_mutex_ =
      absl::make_unique<absl::Mutex>();
  CiphertextPrefixToPrimitivesMap primitives_
      ABSL_GUARDED_BY(primitives_mutex_);

  // Annotations for the set of primitives.
  absl::flat_hash_map<std::string, std::string> annotations_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRIMITIVE_SET_H_
