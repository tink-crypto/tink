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

#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <string>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/internal/ec_util.h"
#include "tink/keyset_handle.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/util/enums.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_siv.pb.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/ed25519.pb.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

using crypto::tink::util::Enums;
using crypto::tink::util::Status;
using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::EcdsaPrivateKey;
using google::crypto::tink::EcdsaSignatureEncoding;
using google::crypto::tink::EciesAeadHkdfPrivateKey;
using google::crypto::tink::Ed25519PrivateKey;
using google::crypto::tink::Keyset;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace test {

int GetTestFileDescriptor(absl::string_view filename, int size,
                          std::string* file_contents) {
  (*file_contents) = subtle::Random::GetRandomBytes(size);
  return GetTestFileDescriptor(filename, *file_contents);
}

int GetTestFileDescriptor(
    absl::string_view filename, absl::string_view file_contents) {
  std::string full_filename =
      absl::StrCat(crypto::tink::test::TmpDir(), "/", filename);
  mode_t mode = S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH;
  int fd = open(full_filename.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (fd == -1) {
    std::clog << "Cannot create file " << full_filename
              << " error: " << errno << std::endl;
    exit(1);
  }
  auto size = file_contents.size();
  if (write(fd, file_contents.data(), size) != size) {
    std::clog << "Failed to write " << size << " bytes to file "
              << full_filename << " error: " << errno << std::endl;

    exit(1);
  }
  close(fd);
  fd = open(full_filename.c_str(), O_RDONLY);
  if (fd == -1) {
    std::clog << "Cannot re-open file " << full_filename
              << " error: " << errno << std::endl;
    exit(1);
  }
  return fd;
}


int GetTestFileDescriptor(absl::string_view filename) {
  std::string full_filename =
      absl::StrCat(crypto::tink::test::TmpDir(), "/", filename);
  mode_t mode = S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH;
  int fd = open(full_filename.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (fd == -1) {
    std::clog << "Cannot create file " << full_filename
              << " error: " << errno << std::endl;
    exit(1);
  }
  return fd;
}

std::string ReadTestFile(std::string filename) {
  std::string full_filename =
      absl::StrCat(crypto::tink::test::TmpDir(), "/", filename);
  int fd = open(full_filename.c_str(), O_RDONLY);
  if (fd == -1) {
    std::clog << "Cannot open file " << full_filename
              << " error: " << errno << std::endl;
    exit(1);
  }
  std::string contents;
  int buffer_size = 128 * 1024;
  auto buffer = absl::make_unique<uint8_t[]>(buffer_size);
  int read_result = read(fd, buffer.get(), buffer_size);
  while (read_result > 0) {
    std::clog << "Read " << read_result << " bytes" << std::endl;
    contents.append(reinterpret_cast<const char*>(buffer.get()), read_result);
    read_result = read(fd, buffer.get(), buffer_size);
  }
  if (read_result < 0) {
    std::clog << "Error reading file " << full_filename
              << " error: " << errno << std::endl;
    exit(1);
  }
  close(fd);
  std::clog << "Read in total " << contents.length() << " bytes" << std::endl;
  return contents;
}

util::StatusOr<std::string> HexDecode(absl::string_view hex) {
  if (hex.size() % 2 != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Input has odd size.");
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
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Not hexadecimal");
    decoded[i / 2] = (decoded[i / 2] << 4) | val;
  }
  return decoded;
}

std::string HexDecodeOrDie(absl::string_view hex) {
  return HexDecode(hex).value();
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

std::string TmpDir() {
  // The Bazel 'test' command sets TEST_TMPDIR.
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

void AddTinkKey(const std::string& key_type, uint32_t key_id,
                const portable_proto::MessageLite& key,
                google::crypto::tink::KeyStatusType key_status,
                google::crypto::tink::KeyData::KeyMaterialType material_type,
                google::crypto::tink::Keyset* keyset) {
  AddKey(key_type, key_id, key, OutputPrefixType::TINK,
         key_status, material_type, keyset);
}

void AddLegacyKey(const std::string& key_type, uint32_t key_id,
                  const portable_proto::MessageLite& key,
                  google::crypto::tink::KeyStatusType key_status,
                  google::crypto::tink::KeyData::KeyMaterialType material_type,
                  google::crypto::tink::Keyset* keyset) {
  AddKey(key_type, key_id, key, OutputPrefixType::LEGACY,
         key_status, material_type, keyset);
}

void AddRawKey(const std::string& key_type, uint32_t key_id,
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

EciesAeadHkdfPrivateKey GetEciesAeadHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type) {
  auto test_key = internal::NewEcKey(Enums::ProtoToSubtle(curve_type)).value();
  EciesAeadHkdfPrivateKey ecies_key;
  ecies_key.set_version(0);
  ecies_key.set_key_value(
      std::string(util::SecretDataAsStringView(test_key.priv)));
  auto public_key = ecies_key.mutable_public_key();
  public_key->set_version(0);
  public_key->set_x(test_key.pub_x);
  public_key->set_y(test_key.pub_y);
  auto params = public_key->mutable_params();
  params->set_ec_point_format(ec_point_format);
  params->mutable_kem_params()->set_curve_type(curve_type);
  params->mutable_kem_params()->set_hkdf_hash_type(hash_type);

  return ecies_key;
}

EciesAeadHkdfPrivateKey GetEciesAesGcmHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type, uint32_t aes_gcm_key_size) {
  auto ecies_key =
      GetEciesAeadHkdfTestKey(curve_type, ec_point_format, hash_type);
  auto params = ecies_key.mutable_public_key()->mutable_params();

  AesGcmKeyFormat key_format;
  key_format.set_key_size(aes_gcm_key_size);
  auto aead_dem = params->mutable_dem_params()->mutable_aead_dem();
  std::unique_ptr<AesGcmKeyManager> key_manager(new AesGcmKeyManager());
  std::string dem_key_type = key_manager->get_key_type();
  aead_dem->set_type_url(dem_key_type);
  aead_dem->set_value(key_format.SerializeAsString());
  return ecies_key;
}

EciesAeadHkdfPrivateKey GetEciesAesCtrHmacHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type, uint32_t aes_ctr_key_size,
    uint32_t aes_ctr_iv_size, google::crypto::tink::HashType hmac_hash_type,
    uint32_t hmac_tag_size, uint32_t hmac_key_size) {
  auto ecies_key =
      GetEciesAeadHkdfTestKey(curve_type, ec_point_format, hash_type);

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

EciesAeadHkdfPrivateKey GetEciesXChaCha20Poly1305HkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type) {
  auto ecies_key =
      GetEciesAeadHkdfTestKey(curve_type, ec_point_format, hash_type);
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

google::crypto::tink::EciesAeadHkdfPrivateKey GetEciesAesSivHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type) {
  auto ecies_key =
      GetEciesAeadHkdfTestKey(curve_type, ec_point_format, hash_type);
  auto params = ecies_key.mutable_public_key()->mutable_params();

  google::crypto::tink::AesSivKeyFormat key_format;
  key_format.set_key_size(64);
  auto aead_dem = params->mutable_dem_params()->mutable_aead_dem();
  AesSivKeyManager key_manager;
  std::string dem_key_type = key_manager.get_key_type();
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
  auto test_key = internal::NewEcKey(Enums::ProtoToSubtle(curve_type)).value();
  EcdsaPrivateKey ecdsa_key;
  ecdsa_key.set_version(0);
  ecdsa_key.set_key_value(
      std::string(util::SecretDataAsStringView(test_key.priv)));
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

Ed25519PrivateKey GetEd25519TestPrivateKey() {
  auto test_key = internal::NewEd25519Key().value();
  Ed25519PrivateKey ed25519_key;
  ed25519_key.set_version(0);
  ed25519_key.set_key_value(test_key->private_key);

  auto public_key = ed25519_key.mutable_public_key();
  public_key->set_version(0);
  public_key->set_key_value(test_key->public_key);

  return ed25519_key;
}

util::Status ZTestUniformString(absl::string_view bytes) {
  double expected = bytes.size() * 8.0 / 2.0;
  double stddev = std::sqrt(static_cast<double>(bytes.size()) * 8.0 / 4.0);
  uint64_t num_set_bits = 0;
  for (uint8_t byte : bytes) {
    // Counting the number of bits set in byte:
    while (byte != 0) {
      num_set_bits++;
      byte = byte & (byte - 1);
    }
  }
  // Check that the number of bits is within 10 stddevs.
  if (abs(static_cast<double>(num_set_bits) - expected) < 10.0 * stddev) {
    return util::OkStatus();
  }
  return util::Status(
      absl::StatusCode::kInternal,
      absl::StrCat("Z test for uniformly distributed variable out of bounds; "
                   "Actual number of set bits was ",
                   num_set_bits, " expected was ", expected,
                   " 10 * standard deviation is 10 * ", stddev, " = ",
                   10.0 * stddev));
}

std::string Rotate(absl::string_view bytes) {
  std::string result(bytes.size(), '\0');
  for (int i = 0; i < bytes.size(); i++) {
    result[i] = (static_cast<uint8_t>(bytes[i]) >> 1) |
                (bytes[(i == 0 ? bytes.size() : i) - 1] << 7);
  }
  return result;
}

util::Status ZTestCrosscorrelationUniformStrings(absl::string_view bytes1,
                                                 absl::string_view bytes2) {
  if (bytes1.size() != bytes2.size()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Strings are not of equal length");
  }
  std::string crossed(bytes1.size(), '\0');
  for (int i = 0; i < bytes1.size(); i++) {
    crossed[i] = bytes1[i] ^ bytes2[i];
  }
  return ZTestUniformString(crossed);
}

util::Status ZTestAutocorrelationUniformString(absl::string_view bytes) {
  std::string rotated(bytes);
  std::vector<int> violations;
  for (int i = 1; i < bytes.size() * 8; i++) {
    rotated = Rotate(rotated);
    auto status = ZTestCrosscorrelationUniformStrings(bytes, rotated);
    if (!status.ok()) {
      violations.push_back(i);
    }
  }
  if (violations.empty()) {
    return util::OkStatus();
  }
  return util::Status(
      absl::StatusCode::kInternal,
      absl::StrCat("Autocorrelation exceeded 10 standard deviation at ",
                   violations.size(),
                   " indices: ", absl::StrJoin(violations, ", ")));
}

}  // namespace test
}  // namespace tink
}  // namespace crypto
