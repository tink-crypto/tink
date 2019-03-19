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

#ifndef TINK_UTIL_TEST_UTIL_H_
#define TINK_UTIL_TEST_UTIL_H_

#include <limits>
#include <string>

#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/deterministic_aead.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/input_stream.h"
#include "tink/keyset_handle.h"
#include "tink/mac.h"
#include "tink/output_stream.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/streaming_aead.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/ed25519.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace test {

// Various utilities for testing.
///////////////////////////////////////////////////////////////////////////////

// Converts a hexadecimal std::string into a std::string of bytes.
// Returns a status if the size of the input is odd or if the input contains
// characters that are not hexadecimal.
crypto::tink::util::StatusOr<std::string> HexDecode(absl::string_view hex);

// Converts a hexadecimal std::string into a std::string of bytes.
// Dies if the input is not a valid hexadecimal std::string.
std::string HexDecodeOrDie(absl::string_view hex);

// Converts a std::string of bytes into a hexadecimal std::string.
std::string HexEncode(absl::string_view bytes);

// Returns a temporary directory suitable for temporary testing files.
std::string TmpDir();

// Adds the given 'keyData' with specified status, key_id, and
// output_prefix_type to the keyset.
void AddKeyData(const google::crypto::tink::KeyData& key_data, uint32_t key_id,
                google::crypto::tink::OutputPrefixType output_prefix,
                google::crypto::tink::KeyStatusType key_status,
                google::crypto::tink::Keyset* keyset);

// Adds the given 'key' with specified parameters and output_prefix_type=TINK
// to the specified 'keyset'.
void AddTinkKey(const std::string& key_type, uint32_t key_id,
                const portable_proto::MessageLite& key,
                google::crypto::tink::KeyStatusType key_status,
                google::crypto::tink::KeyData::KeyMaterialType material_type,
                google::crypto::tink::Keyset* keyset);

// Adds the given 'key' with specified parameters and output_prefix_type=LEGACY
// to the specified 'keyset'.
void AddLegacyKey(const std::string& key_type, uint32_t key_id,
                  const portable_proto::MessageLite& key,
                  google::crypto::tink::KeyStatusType key_status,
                  google::crypto::tink::KeyData::KeyMaterialType material_type,
                  google::crypto::tink::Keyset* keyset);

// Adds the given 'key' with specified parameters and output_prefix_type=RAW
// to the specified 'keyset'.
void AddRawKey(const std::string& key_type, uint32_t key_id,
               const portable_proto::MessageLite& key,
               google::crypto::tink::KeyStatusType key_status,
               google::crypto::tink::KeyData::KeyMaterialType material_type,
               google::crypto::tink::Keyset* keyset);

// Generates a fresh test key for ECIES-AEAD-HKDF for the given curve,
// using AesGcm with the specified key size as AEAD, and HKDF with 'hash_type'.
google::crypto::tink::EciesAeadHkdfPrivateKey GetEciesAesGcmHkdfTestKey(
    subtle::EllipticCurveType curve_type, subtle::EcPointFormat ec_point_format,
    subtle::HashType hash_type, uint32_t aes_gcm_key_size);

// Generates a fresh test key for ECIES-AEAD-HKDF for the given curve,
// using AesGcm with the specified key size as AEAD, and HKDF with 'hash_type'.
google::crypto::tink::EciesAeadHkdfPrivateKey GetEciesAesGcmHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type, uint32_t aes_gcm_key_size);

// Generates a fresh test key for EC DSA for the given 'curve_type', 'hash_type'
// and 'encoding'.
google::crypto::tink::EcdsaPrivateKey GetEcdsaTestPrivateKey(
    subtle::EllipticCurveType curve_type, subtle::HashType hash_type,
    subtle::EcdsaSignatureEncoding encoding);

// Generates a fresh test key for EC DSA for the given 'curve_type', 'hash_type'
// and 'encoding'.
google::crypto::tink::EcdsaPrivateKey GetEcdsaTestPrivateKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::HashType hash_type,
    google::crypto::tink::EcdsaSignatureEncoding encoding);

// Generates a fresh test key for ED25519.
google::crypto::tink::Ed25519PrivateKey GetEd25519TestPrivateKey();

// A dummy implementation of Aead-interface.
// An instance of DummyAead can be identified by a name specified
// as a parameter of the constructor.
class DummyAead : public Aead {
 public:
  explicit DummyAead(absl::string_view aead_name) : aead_name_(aead_name) {}

  // Computes a dummy ciphertext, which is concatenation of provided 'plaintext'
  // with the name of this DummyAead.
  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view associated_data) const override {
    return absl::StrCat(aead_name_.size(), ":", associated_data.size(), ":",
                        aead_name_, associated_data, plaintext);
  }

  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view associated_data) const override {
    std::string prefix = absl::StrCat(aead_name_.size(), ":", associated_data.size(),
                                 ":", aead_name_, associated_data);
    if (!StartsWith(ciphertext, prefix)) {
      return crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT,
          "Dummy operation failed.");
    }
    ciphertext.remove_prefix(prefix.size());
    return std::string(ciphertext);
  }

 private:
  std::string aead_name_;
};

// A dummy implementation of DeterministicAead-interface.
// An instance of DummyDeterministicAead can be identified by a name specified
// as a parameter of the constructor.
// The implementation is the same as DummyAead.
class DummyDeterministicAead : public DeterministicAead {
 public:
  explicit DummyDeterministicAead(absl::string_view daead_name)
      : aead_(daead_name) {}

  crypto::tink::util::StatusOr<std::string> EncryptDeterministically(
      absl::string_view plaintext,
      absl::string_view associated_data) const override {
    return aead_.Encrypt(plaintext, associated_data);
  }

  crypto::tink::util::StatusOr<std::string> DecryptDeterministically(
      absl::string_view ciphertext,
      absl::string_view associated_data) const override {
    return aead_.Decrypt(ciphertext, associated_data);
  }

 private:
  DummyAead aead_;
};

// A dummy implementation of StreamingAead-interface.
// An instance of DummyStreamingAead can be identified by a name specified
// as a parameter of the constructor.
class DummyStreamingAead : public StreamingAead {
 public:
  explicit DummyStreamingAead(absl::string_view streaming_aead_name)
      : streaming_aead_name_(streaming_aead_name) {}

  // Writes to 'ciphertext_destination' the name of this instance
  // followed by 'associated_data', and returns 'ciphertext_destination'
  // as the encrypting stream.
  crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::OutputStream>>
  NewEncryptingStream(
      std::unique_ptr<crypto::tink::OutputStream> ciphertext_destination,
      absl::string_view associated_data) override {
    auto header = absl::StrCat(streaming_aead_name_, associated_data);
    void* buffer;
    auto next_result = ciphertext_destination->Next(&buffer);
    if (!next_result.status().ok()) return next_result.status();
    if (next_result.ValueOrDie() < header.size()) {
      return crypto::tink::util::Status(crypto::tink::util::error::INTERNAL,
                                        "Buffer too small");
    }
    if (header.size() > std::numeric_limits<int>::max()) {
      return crypto::tink::util::Status(crypto::tink::util::error::INTERNAL,
                                        "Input too large");
    }
    const int header_size = static_cast<int>(header.size());
    memcpy(buffer, header.data(), header.size());
    ciphertext_destination->BackUp(next_result.ValueOrDie() - header_size);
    return std::move(ciphertext_destination);
  }

  // Reads a prefix from 'ciphertext_source' and verifies that it starts
  // with the name of this instance, followed by 'associated_data'.
  // Returns 'ciphertext_source' as the decrypting stream.
  crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::InputStream>>
  NewDecryptingStream(
      std::unique_ptr<crypto::tink::InputStream> ciphertext_source,
      absl::string_view associated_data) override {
    auto header = absl::StrCat(streaming_aead_name_, associated_data);
    const void* buffer;
    auto next_result = ciphertext_source->Next(&buffer);
    if (!next_result.status().ok()) return next_result.status();
    if (next_result.ValueOrDie() < header.size()) {
      return crypto::tink::util::Status(crypto::tink::util::error::INTERNAL,
                                        "Buffer too small");
    }
    if (header.size() > std::numeric_limits<int>::max()) {
      return crypto::tink::util::Status(crypto::tink::util::error::INTERNAL,
                                        "Input too large");
    }
    const int header_size = static_cast<int>(header.size());
    if (!memcmp(buffer, header.data(), header.size())) {
      return crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "Corrupted header");
    }
    ciphertext_source->BackUp(next_result.ValueOrDie() - header_size);
    return std::move(ciphertext_source);
  }

 private:
  std::string streaming_aead_name_;
};

// A dummy implementation of HybridEncrypt-interface.
// An instance of DummyHybridEncrypt can be identified by a name specified
// as a parameter of the constructor.
class DummyHybridEncrypt : public HybridEncrypt {
 public:
  explicit DummyHybridEncrypt(absl::string_view hybrid_name)
      : dummy_aead_(absl::StrCat("DummyHybrid:", hybrid_name)) {}

  // Computes a dummy ciphertext, which is concatenation of provided 'plaintext'
  // with the name of this DummyHybridEncrypt.
  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view context_info) const override {
    return dummy_aead_.Encrypt(plaintext, context_info);
  }

 private:
  DummyAead dummy_aead_;
};

// A dummy implementation of HybridDecrypt-interface.
// An instance of DummyHybridDecrypt can be identified by a name specified
// as a parameter of the constructor.
class DummyHybridDecrypt : public HybridDecrypt {
 public:
  explicit DummyHybridDecrypt(absl::string_view hybrid_name)
      : dummy_aead_(absl::StrCat("DummyHybrid:", hybrid_name)) {}

  // Decrypts a dummy ciphertext, which should be a concatenation
  // of a plaintext with the name of this DummyHybridDecrypt.
  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view context_info) const override {
    return dummy_aead_.Decrypt(ciphertext, context_info);
  }

 private:
  DummyAead dummy_aead_;
};

// A dummy implementation of PublicKeySign-interface.
// An instance of DummyPublicKeySign can be identified by a name specified
// as a parameter of the constructor.
class DummyPublicKeySign : public PublicKeySign {
 public:
  explicit DummyPublicKeySign(absl::string_view signature_name)
      : dummy_aead_(absl::StrCat("DummySign:", signature_name)) {}

  // Computes a dummy signature, which is a concatenation of 'data'
  // with the name of this DummyPublicKeySign.
  crypto::tink::util::StatusOr<std::string> Sign(
      absl::string_view data) const override {
    return dummy_aead_.Encrypt("", data);
  }

 private:
  DummyAead dummy_aead_;
};

// A dummy implementation of PublicKeyVerify-interface.
// An instance of DummyPublicKeyVerify can be identified by a name specified
// as a parameter of the constructor.
class DummyPublicKeyVerify : public PublicKeyVerify {
 public:
  explicit DummyPublicKeyVerify(absl::string_view signature_name)
      : dummy_aead_(absl::StrCat("DummySign:", signature_name)) {}

  // Verifies a dummy signature, should be a concatenation of the name
  // of this DummyPublicKeyVerify with the provided 'data'.
  crypto::tink::util::Status Verify(absl::string_view signature,
                                    absl::string_view data) const override {
    return dummy_aead_.Decrypt(signature, data).status();
  }

 private:
  DummyAead dummy_aead_;
};

// A dummy implementation of Mac-interface.
// An instance of DummyMac can be identified by a name specified
// as a parameter of the constructor.
class DummyMac : public Mac {
 public:
  explicit DummyMac(const std::string& mac_name)
      : dummy_aead_(absl::StrCat("DummyMac:", mac_name)) {}

  // Computes a dummy MAC, which is concatenation of provided 'data'
  // with the name of this DummyMac.
  crypto::tink::util::StatusOr<std::string> ComputeMac(
      absl::string_view data) const override {
    return dummy_aead_.Encrypt("", data);
  }

  crypto::tink::util::Status VerifyMac(absl::string_view mac,
                                       absl::string_view data) const override {
    return dummy_aead_.Decrypt(mac, data).status();
  }

 private:
  DummyAead dummy_aead_;
};

// A dummy implementation of KeysetWriter-interface.
class DummyKeysetWriter : public KeysetWriter {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<DummyKeysetWriter>> New(
      std::unique_ptr<std::ostream> destination_stream) {
    std::unique_ptr<DummyKeysetWriter> writer(
        new DummyKeysetWriter(std::move(destination_stream)));
    return std::move(writer);
  }

  crypto::tink::util::Status Write(
      const google::crypto::tink::Keyset& keyset) override {
    return crypto::tink::util::Status::OK;
  }

  crypto::tink::util::Status Write(
      const google::crypto::tink::EncryptedKeyset& encrypted_keyset) override {
    return crypto::tink::util::Status::OK;
  }

 private:
  explicit DummyKeysetWriter(std::unique_ptr<std::ostream> destination_stream)
      : destination_stream_(std::move(destination_stream)) {}

  std::unique_ptr<std::ostream> destination_stream_;
};

}  // namespace test
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_TEST_UTIL_H_
