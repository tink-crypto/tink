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

#include "cc/util/test_util.h"

#include <stdarg.h>
#include <stdlib.h>

#include "cc/keyset_handle.h"
#include "cc/binary_keyset_reader.h"
#include "cc/cleartext_keyset_handle.h"
#include "cc/aead/aes_gcm_key_manager.h"
#include "cc/subtle/subtle_util_boringssl.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "proto/aes_gcm.pb.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::EciesAeadHkdfPrivateKey;
using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::Keyset;
using google::crypto::tink::OutputPrefixType;
using crypto::tink::util::error::Code;
using crypto::tink::util::Status;

namespace util = crypto::tink::util;

namespace crypto {
namespace tink {
namespace test {

util::StatusOr<std::string> HexDecode(google::protobuf::StringPiece hex) {
  if (hex.size() % 2 != 0) {
    return util::Status(util::error::INVALID_ARGUMENT, "Input has odd size.");
  }
  std::string decoded(hex.size() / 2, static_cast<char>(0));
  for (int i = 0; i < hex.size(); ++i) {
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

std::string HexDecodeOrDie(google::protobuf::StringPiece hex) {
  return HexDecode(hex).ValueOrDie();
}

std::string HexEncode(google::protobuf::StringPiece bytes) {
  std::string hexchars = "0123456789abcdef";
  std::string res(bytes.size() * 2, static_cast<char>(255));
  for (int i = 0; i < bytes.size(); ++i) {
    uint8_t c = static_cast<uint8_t>(bytes[i]);
    res[2 * i] = hexchars[c / 16];
    res[2 * i + 1] = hexchars[c % 16];
  }
  return res;
}

std::unique_ptr<KeysetHandle> GetKeysetHandle(const Keyset& keyset) {
  auto reader = std::move(
      BinaryKeysetReader::New(keyset.SerializeAsString()).ValueOrDie());
  return std::move(CleartextKeysetHandle::Read(std::move(reader)).ValueOrDie());
}

void AddKey(
    const std::string& key_type,
    uint32_t key_id,
    const google::protobuf::Message& new_key,
    google::crypto::tink::OutputPrefixType output_prefix,
    google::crypto::tink::KeyStatusType key_status,
    google::crypto::tink::KeyData::KeyMaterialType material_type,
    google::crypto::tink::Keyset* keyset) {
  Keyset::Key* key = keyset->add_key();
  key->set_output_prefix_type(output_prefix);
  key->set_key_id(key_id);
  key->set_status(key_status);
  key->mutable_key_data()->set_type_url(key_type);
  key->mutable_key_data()->set_key_material_type(material_type);
  key->mutable_key_data()->set_value(new_key.SerializeAsString());
}

void AddTinkKey(
    const std::string& key_type,
    uint32_t key_id,
    const google::protobuf::Message& key,
    google::crypto::tink::KeyStatusType key_status,
    google::crypto::tink::KeyData::KeyMaterialType material_type,
    google::crypto::tink::Keyset* keyset) {
  AddKey(key_type, key_id, key, OutputPrefixType::TINK,
         key_status, material_type, keyset);
}

void AddLegacyKey(
    const std::string& key_type,
    uint32_t key_id,
    const google::protobuf::Message& key,
    google::crypto::tink::KeyStatusType key_status,
    google::crypto::tink::KeyData::KeyMaterialType material_type,
    google::crypto::tink::Keyset* keyset) {
  AddKey(key_type, key_id, key, OutputPrefixType::LEGACY,
         key_status, material_type, keyset);
}

void AddRawKey(
    const std::string& key_type,
    uint32_t key_id,
    const google::protobuf::Message& key,
    google::crypto::tink::KeyStatusType key_status,
    google::crypto::tink::KeyData::KeyMaterialType material_type,
    google::crypto::tink::Keyset* keyset) {
  AddKey(key_type, key_id, key, OutputPrefixType::RAW,
         key_status, material_type, keyset);
}

EciesAeadHkdfPrivateKey GetEciesAesGcmHkdfTestKey(
    EllipticCurveType curve_type,
    EcPointFormat ec_point_format,
    HashType hash_type,
    uint32_t aes_gcm_key_size) {
  auto test_key = SubtleUtilBoringSSL::GetNewEcKey(curve_type).ValueOrDie();
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
  key_format.set_key_size(24);
  auto aead_dem = params->mutable_dem_params()->mutable_aead_dem();
  std::unique_ptr<AesGcmKeyManager> key_manager(new AesGcmKeyManager());
  std::string dem_key_type = key_manager->get_key_type();
  aead_dem->set_type_url(dem_key_type);
  aead_dem->set_value(key_format.SerializeAsString());
  return ecies_key;
}

}  // namespace test
}  // namespace tink
}  // namespace crypto
