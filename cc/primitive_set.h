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

#include <unordered_map>
#include <vector>

#include "cc/crypto_format.h"
#include "cc/util/errors.h"
#include "cc/util/statusor.h"
#include "proto/tink.pb.h"

namespace cloud {
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
// determines the id of the primitive from the set.
//
// PrimitiveSet is a public class to allow its use in implementations
// of custom primitives.
//
// TODO(przydatek): make it thread-safe.
template <class P>
class PrimitiveSet {
 public:
  template <class P2>
  class Entry {
   public:
    Entry(std::unique_ptr<P2> primitive, std::string identifier,
          google::cloud::crypto::tink::KeyStatusType status) :
        primitive_(std::move(primitive)),
        identifier_(identifier),
        status_(status) {
    }
    P2& get_primitive() const {
    return *primitive_;
    }
    const std::string& get_identifier() const {
      return identifier_;
    }
    const google::cloud::crypto::tink::KeyStatusType get_status() const {
      return status_;
    }
   private:
    std::unique_ptr<P> primitive_;
    std::string identifier_;
    google::cloud::crypto::tink::KeyStatusType status_;
  };

  PrimitiveSet<P>() : primary_(nullptr) {}

  typedef std::vector<Entry<P>> Primitives;

  // Returns the entry with the primary primitive.
  const Entry<P>* get_primary() const {
    return primary_;
  }

  // Returns all primitives that use RAW prefix.
  util::StatusOr<Primitives*> get_raw_primitives() {
    return get_primitives(CryptoFormat::kRawPrefix);
  }

  // Returns the entries with primitive identifed by 'identifier'.
  util::StatusOr<Primitives*> get_primitives(
      const std::string& identifier) {
    typename CiphertextPrefixToPrimitivesMap::iterator found =
        primitives_.find(identifier);
    if (found == primitives_.end()) {
      return ToStatusF(util::error::NOT_FOUND,
                       "No primitives found for identifier '%s'.",
                       identifier.c_str());
    }
    return &(found->second);
  }

  // Sets the given 'primary' as as the primary primitive of this set.
  void set_primary(Entry<P>* primary) {
    primary_ = primary;
  }

  // Adds 'primitive' to this set for the specified 'key'.
  util::StatusOr<Entry<P>*> AddPrimitive(
      std::unique_ptr<P> primitive,
      google::cloud::crypto::tink::Keyset::Key key) {
    auto identifier_result = CryptoFormat::get_output_prefix(key);
    if (!identifier_result.ok()) return identifier_result.status();
    std::string identifier = identifier_result.ValueOrDie();
    primitives_[identifier].push_back(Entry<P>(std::move(primitive),
                                               identifier,
                                               key.status()));
    return &(primitives_[identifier].back());
  }

 private:
  Entry<P>* primary_;
  typedef std::unordered_map<std::string, Primitives>
      CiphertextPrefixToPrimitivesMap;
  CiphertextPrefixToPrimitivesMap primitives_;
};


}  // namespace tink
}  // namespace crypto
}  // namespace cloud

#endif  // TINK_PRIMITIVE_SET_H_
