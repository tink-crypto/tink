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

#include "experimental/pqcrypto/cecpq2/util/test_util.h"

#include "openssl/curve25519.h"
#include "openssl/hrss.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "experimental/pqcrypto/cecpq2/subtle/cecpq2_subtle_boringssl_util.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/enums.h"
#include "proto/aes_ctr.pb.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/hmac.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace test {

google::crypto::tink::Cecpq2AeadHkdfPrivateKey GetCecpq2AeadHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type) {
  google::crypto::tink::Cecpq2AeadHkdfPrivateKey cecpq2_key_pair_proto;
  cecpq2_key_pair_proto.set_version(0);

  auto cecpq2_key_pair_or_status =
      pqc::GenerateCecpq2Keypair(util::Enums::ProtoToSubtle(curve_type));
  auto cecpq2_key_pair = std::move(cecpq2_key_pair_or_status.ValueOrDie());

  std::string hrss_priv_key_seed_str(
      reinterpret_cast<const char *>(
          cecpq2_key_pair.hrss_key_pair.hrss_private_key_seed.data()),
      HRSS_GENERATE_KEY_BYTES);
  cecpq2_key_pair_proto.set_hrss_private_key_seed(hrss_priv_key_seed_str);

  cecpq2_key_pair_proto.set_x25519_private_key(
      std::string(reinterpret_cast<const char *>(
                      cecpq2_key_pair.x25519_key_pair.priv.data()),
                  X25519_PRIVATE_KEY_LEN));

  auto public_key = cecpq2_key_pair_proto.mutable_public_key();
  public_key->set_version(0);
  public_key->set_x25519_public_key_x(cecpq2_key_pair.x25519_key_pair.pub_x);
  public_key->set_x25519_public_key_y(cecpq2_key_pair.x25519_key_pair.pub_y);
  public_key->set_hrss_public_key_marshalled(
      cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);

  auto params = public_key->mutable_params();
  params->mutable_kem_params()->set_ec_point_format(ec_point_format);
  params->mutable_kem_params()->set_curve_type(curve_type);
  params->mutable_kem_params()->set_hkdf_hash_type(hash_type);

  return cecpq2_key_pair_proto;
}

google::crypto::tink::Cecpq2AeadHkdfPrivateKey GetCecpq2AesGcmHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type, uint32_t aes_gcm_key_size) {
  auto cecpq2_key =
      GetCecpq2AeadHkdfTestKey(curve_type, ec_point_format, hash_type);
  auto params = cecpq2_key.mutable_public_key()->mutable_params();

  google::crypto::tink::AesGcmKeyFormat key_format;
  key_format.set_key_size(aes_gcm_key_size);
  auto aead_dem = params->mutable_dem_params()->mutable_aead_dem();
  std::unique_ptr<AesGcmKeyManager> key_manager(new AesGcmKeyManager());
  std::string dem_key_type = key_manager->get_key_type();
  aead_dem->set_type_url(dem_key_type);
  aead_dem->set_value(key_format.SerializeAsString());
  return cecpq2_key;
}

google::crypto::tink::Cecpq2AeadHkdfPrivateKey GetCecpq2AesCtrHmacHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type, uint32_t aes_ctr_key_size,
    uint32_t aes_ctr_iv_size, google::crypto::tink::HashType hmac_hash_type,
    uint32_t hmac_tag_size, uint32_t hmac_key_size) {
  auto ecies_key =
      GetCecpq2AeadHkdfTestKey(curve_type, ec_point_format, hash_type);

  google::crypto::tink::AesCtrHmacAeadKeyFormat key_format;
  auto aes_ctr_key_format = key_format.mutable_aes_ctr_key_format();
  auto aes_ctr_params = aes_ctr_key_format->mutable_params();
  aes_ctr_params->set_iv_size(aes_ctr_iv_size);
  aes_ctr_key_format->set_key_size(aes_ctr_key_size);

  auto hmac_key_format = key_format.mutable_hmac_key_format();
  auto hmac_params = hmac_key_format->mutable_params();
  hmac_params->set_hash(hmac_hash_type);
  hmac_params->set_tag_size(hmac_tag_size);
  hmac_key_format->set_key_size(hmac_key_size);

  auto params = ecies_key.mutable_public_key()->mutable_params();
  auto aead_dem = params->mutable_dem_params()->mutable_aead_dem();

  std::unique_ptr<AesCtrHmacAeadKeyManager> key_manager(
      new AesCtrHmacAeadKeyManager());
  std::string dem_key_type = key_manager->get_key_type();
  aead_dem->set_type_url(dem_key_type);
  aead_dem->set_value(key_format.SerializeAsString());
  return ecies_key;
}

google::crypto::tink::Cecpq2AeadHkdfPrivateKey
GetCecpq2XChaCha20Poly1305HkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type) {
  auto ecies_key =
      GetCecpq2AeadHkdfTestKey(curve_type, ec_point_format, hash_type);
  auto params = ecies_key.mutable_public_key()->mutable_params();

  google::crypto::tink::XChaCha20Poly1305KeyFormat key_format;
  auto aead_dem = params->mutable_dem_params()->mutable_aead_dem();
  std::unique_ptr<XChaCha20Poly1305KeyManager> key_manager(
      new XChaCha20Poly1305KeyManager());
  std::string dem_key_type = key_manager->get_key_type();
  aead_dem->set_type_url(dem_key_type);
  aead_dem->set_value(key_format.SerializeAsString());

  return ecies_key;
}

}  // namespace test
}  // namespace tink
}  // namespace crypto
