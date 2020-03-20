// Copyright 2018 Google Inc.
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

#include "tink/util/keyset_util.h"

#include <cstdint>
#include <random>

#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

namespace {

using google::crypto::tink::Keyset;

uint32_t NewKeyId() {
  std::random_device rd;
  std::minstd_rand0 gen(rd());
  std::uniform_int_distribution<uint32_t> dist;
  return dist(gen);
}

}  // namespace

uint32_t GenerateUnusedKeyId(const Keyset& keyset) {
  while (true) {
    uint32_t key_id = NewKeyId();
    bool already_exists = false;
    for (auto& key : keyset.key()) {
      if (key.key_id() == key_id) {
        already_exists = true;
        break;
      }
    }
    if (!already_exists) return key_id;
  }
}

}  // namespace tink
}  // namespace crypto
