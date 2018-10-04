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

#ifndef TINK_DAEAD_DAEAD_CONFIG_H_
#define TINK_DAEAD_DAEAD_CONFIG_H_

#include "tink/config.h"
#include "tink/util/status.h"
#include "proto/config.pb.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Static methods and constants for registering with the Registry
// all instances of DeterministicAead key types supported in a release of Tink.
//
// To register all DeterministicAead key types from the current Tink release
// one can do:
//
//   auto status = DeterministicAeadConfig::Register();
//
// For more information on creation and usage of DeterministicAead instances
// see DeterministicAeadFactory.
class DeterministicAeadConfig {
 public:
  static constexpr char kCatalogueName[] = "TinkDeterministicAead";
  static constexpr char kPrimitiveName[] = "DeterministicAead";

  // Returns config of DeterministicAead implementations supported
  // in the current Tink release.
  static const google::crypto::tink::RegistryConfig& Latest();

  // Registers key managers for all DeterministicAead key types
  // from the current Tink release.
  static crypto::tink::util::Status Register();

 private:
  DeterministicAeadConfig() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_DAEAD_DAEAD_CONFIG_H_
