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

#include "tink/util/test_util.h"

#include <stdarg.h>
#include <stdlib.h>
#include <cstdlib>

#include "absl/memory/memory.h"
#include "tink/keyset_handle.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_gcm.pb.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::EcdsaPrivateKey;
using google::crypto::tink::EcdsaSignatureEncoding;
using google::crypto::tink::EciesAeadHkdfPrivateKey;
using google::crypto::tink::Keyset;
using google::crypto::tink::OutputPrefixType;
using crypto::tink::util::Enums;
using crypto::tink::util::Status;
using crypto::tink::util::error::Code;


namespace crypto {
namespace tink {
namespace test {

util::StatusOr<std::string> HexDecode(absl::string_view hex) {
  if (hex.size() % 2 != 0) {
    return util::Status(util::error::INVALID_ARGUMENT, "Input has odd size.");
  }
  std::string decoded(hex.size() / 2, static_cast<char>(0));
  for (size_t i = 0; i < hex.size(); ++i) {
    char c = hex[i];
    char val;
    if ('0' <= c && c <= '9')
      val = c - '0';
    else if ('a' <= c && c <= 'f')
      val = c - 'a' + 10;
    else if ('A' <= c && c <= 'F')
      val = c - 'A' + 10;
    else
      return util::Status(util::error::INVALID_ARGUMENT, "Not hexadecimal");
    decoded[i / 2] = (decoded[i / 2] << 4) | val;
  }
  return decoded;
}

std::string HexDecodeOrDie(absl::string_view hex) {
  return HexDecode(hex).ValueOrDie();
}

std::string HexEncode(absl::string_view bytes) {
  std::string hexchars = "0123456789abcdef";
  std::string res(bytes.size() * 2, static_cast<char>(255));
  for (size_t i = 0; i < bytes.size(); ++i) {
    uint8_t c = static_cast<uint8_t>(bytes[i]);
    res[2 * i] = hexchars[c / 16];
    res[2 * i + 1] = hexchars[c % 16];
  }
  return res;
}

#if defined(PLATFORM_GOOGLE)
std::string TmpDir() { return FLAGS_test_tmpdir; }
#else
std::string TmpDir() {
  // 'bazel test' sets TEST_TMPDIR
  const char* env = getenv("TEST_TMPDIR");
  if (env && env[0] != '\0') {
    return env;
  }
  env = getenv("TMPDIR");
  if (env && env[0] != '\0') {
    return env;
  }
  return "/tmp";
}
#endif

void AddKeyData(
    const google::crypto::tink::KeyData& key_data,
    uint32_t key_id,
    google::crypto::tink::OutputPrefixType output_prefix,
    google::crypto::tink::KeyStatusType key_status,
    google::crypto::tink::Keyset* keyset) {
  Keyset::Key* key = keyset->add_key();
  key->set_output_prefix_type(output_prefix);
  key->set_key_id(key_id);
  key->set_status(key_status);
  *key->mutable_key_data() = key_data;
}

void AddKey(const std::string& key_type, uint32_t key_id,
            const portable_proto::MessageLite& new_key,
            google::crypto::tink::OutputPrefixType output_prefix,
            google::crypto::tink::KeyStatusType key_status,
            google::crypto::tink::KeyData::KeyMaterialType material_type,
            google::crypto::tink::Keyset* keyset) {
  google::crypto::tink::KeyData key_data;
  key_data.set_type_url(key_type);
  key_data.set_key_material_type(material_type);
  key_data.set_value(new_key.SerializeAsString());
  AddKeyData(key_data, key_id, output_prefix, key_status, keyset);
}

void AddTinkKey(
    const std::string& key_type,
    uint32_t key_id,
    const portable_proto::MessageLite& key,
    google::crypto::tink::KeyStatusType key_status,
    google::crypto::tink::KeyData::KeyMaterialType material_type,
    google::crypto::tink::Keyset* keyset) {
  AddKey(key_type, key_id, key, OutputPrefixType::TINK,
         key_status, material_type, keyset);
}

void AddLegacyKey(
    const std::string& key_type,
    uint32_t key_id,
    const portable_proto::MessageLite& key,
    google::crypto::tink::KeyStatusType key_status,
    google::crypto::tink::KeyData::KeyMaterialType material_type,
    google::crypto::tink::Keyset* keyset) {
  AddKey(key_type, key_id, key, OutputPrefixType::LEGACY,
         key_status, material_type, keyset);
}

void AddRawKey(
    const std::string& key_type,
    uint32_t key_id,
    const portable_proto::MessageLite& key,
    google::crypto::tink::KeyStatusType key_status,
    google::crypto::tink::KeyData::KeyMaterialType material_type,
    google::crypto::tink::Keyset* keyset) {
  AddKey(key_type, key_id, key, OutputPrefixType::RAW,
         key_status, material_type, keyset);
}

EciesAeadHkdfPrivateKey GetEciesAesGcmHkdfTestKey(
    subtle::EllipticCurveType curve_type,
    subtle::EcPointFormat ec_point_format,
    subtle::HashType hash_type,
    uint32_t aes_gcm_key_size) {
  return GetEciesAesGcmHkdfTestKey(
      Enums::SubtleToProto(curve_type),
      Enums::SubtleToProto(ec_point_format),
      Enums::SubtleToProto(hash_type),
      aes_gcm_key_size);
}

EciesAeadHkdfPrivateKey GetEciesAesGcmHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type,
    uint32_t aes_gcm_key_size) {
  auto test_key = subtle::SubtleUtilBoringSSL::GetNewEcKey(
      Enums::ProtoToSubtle(curve_type)).ValueOrDie();
  EciesAeadHkdfPrivateKey ecies_key;
  ecies_key.set_version(0);
  ecies_key.set_key_value(test_key.priv);
  auto public_key = ecies_key.mutable_public_key();
  public_key->set_version(0);
  public_key->set_x(test_key.pub_x);
  public_key->set_y(test_key.pub_y);
  auto params = public_key->mutable_params();
  params->set_ec_point_format(ec_point_format);
  params->mutable_kem_params()->set_curve_type(curve_type);
  params->mutable_kem_params()->set_hkdf_hash_type(hash_type);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(aes_gcm_key_size);
  auto aead_dem = params->mutable_dem_params()->mutable_aead_dem();
  std::unique_ptr<AesGcmKeyManager> key_manager(new AesGcmKeyManager());
  std::string dem_key_type = key_manager->get_key_type();
  aead_dem->set_type_url(dem_key_type);
  aead_dem->set_value(key_format.SerializeAsString());
  return ecies_key;
}

EcdsaPrivateKey GetEcdsaTestPrivateKey(
    subtle::EllipticCurveType curve_type, subtle::HashType hash_type,
    subtle::EcdsaSignatureEncoding encoding) {
  return GetEcdsaTestPrivateKey(Enums::SubtleToProto(curve_type),
                                Enums::SubtleToProto(hash_type),
                                Enums::SubtleToProto(encoding));
}

EcdsaPrivateKey GetEcdsaTestPrivateKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::HashType hash_type,
    google::crypto::tink::EcdsaSignatureEncoding encoding) {
  auto test_key = subtle::SubtleUtilBoringSSL::GetNewEcKey(
      Enums::ProtoToSubtle(curve_type)).ValueOrDie();
  EcdsaPrivateKey ecdsa_key;
  ecdsa_key.set_version(0);
  ecdsa_key.set_key_value(test_key.priv);
  auto public_key = ecdsa_key.mutable_public_key();
  public_key->set_version(0);
  public_key->set_x(test_key.pub_x);
  public_key->set_y(test_key.pub_y);
  auto params = public_key->mutable_params();
  params->set_hash_type(hash_type);
  params->set_curve(curve_type);
  params->set_encoding(encoding);
  return ecdsa_key;
}

}  // namespace test
}  // namespace tink
}  // namespace crypto
