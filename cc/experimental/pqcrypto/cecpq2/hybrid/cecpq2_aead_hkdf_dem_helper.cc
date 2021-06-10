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

#include "experimental/pqcrypto/cecpq2/hybrid/cecpq2_aead_hkdf_dem_helper.h"

#include <utility>

#include "absl/memory/memory.h"
#include "tink/aead.h"
#include "tink/deterministic_aead.h"
#include "tink/registry.h"
#include "tink/util/errors.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::AeadOrDaead;
using ::google::crypto::tink::KeyTemplate;

// Internal implementaton of the Cecpq2AeadHkdfDemHelper class, parametrized by
// the Primitive used for data encapsulation (i.e Aead or DeterministicAead).
template <class EncryptionPrimitive>
class Cecpq2AeadHkdfDemHelperImpl : public Cecpq2AeadHkdfDemHelper {
 public:
  explicit Cecpq2AeadHkdfDemHelperImpl(
      const google::crypto::tink::KeyTemplate& key_template)
      : key_template_(key_template) {}

  crypto::tink::util::StatusOr<
      std::unique_ptr<crypto::tink::subtle::AeadOrDaead>>
  GetAeadOrDaead(const util::SecretData& seed) const override {
    if (seed.size() < 32) {
      return util::Status(util::error::INTERNAL,
                          "Seed length is smaller than 32 bytes "
                          "and thus not post-quantum secure.");
    }
    std::string seed_str(util::SecretDataAsStringView(seed));
    util::IstreamInputStream input_stream{
        absl::make_unique<std::stringstream>(seed_str)};
    auto key_or = internal::RegistryImpl::GlobalInstance().DeriveKey(
        key_template_, &input_stream);
    if (!key_or.ok()) return key_or.status();
    auto key = std::move(key_or).ValueOrDie();
    util::StatusOr<std::unique_ptr<EncryptionPrimitive>> primitive_or =
        Registry::GetPrimitive<EncryptionPrimitive>(key);
    if (!primitive_or.ok()) return primitive_or.status();
    return absl::make_unique<AeadOrDaead>(std::move(primitive_or.ValueOrDie()));
  }

  crypto::tink::util::StatusOr<uint32_t> GetKeyMaterialSize() const override {
    absl::string_view dem_type_url = key_template_.type_url();
    // For AES-SIV, two keys of 32 bytes each are needed
    if (dem_type_url == "type.googleapis.com/google.crypto.tink.AesSivKey") {
      return 64;
    } else if (
        dem_type_url == "type.googleapis.com/google.crypto.tink.AesGcmKey" ||
        dem_type_url ==
            "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key") {
      return 32;
    } else {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Unsupported DEM key type '%s'.", dem_type_url);
    }
  }

 private:
  const google::crypto::tink::KeyTemplate key_template_;
};
}  // namespace

// static
util::StatusOr<std::unique_ptr<const Cecpq2AeadHkdfDemHelper>>
Cecpq2AeadHkdfDemHelper::New(const KeyTemplate& dem_key_template) {
  const std::string& dem_type_url = dem_key_template.type_url();
  if (dem_type_url == "type.googleapis.com/google.crypto.tink.AesGcmKey" ||
      dem_type_url ==
          "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key") {
    return {
        absl::make_unique<Cecpq2AeadHkdfDemHelperImpl<Aead>>(dem_key_template)};
  } else if (dem_type_url ==
             "type.googleapis.com/google.crypto.tink.AesSivKey") {
    return {absl::make_unique<Cecpq2AeadHkdfDemHelperImpl<DeterministicAead>>(
        dem_key_template)};
  }
  return ToStatusF(util::error::INVALID_ARGUMENT,
                   "Unsupported DEM key type '%s'.", dem_type_url);
}

}  // namespace tink
}  // namespace crypto
