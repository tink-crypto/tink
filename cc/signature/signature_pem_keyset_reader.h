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

#ifndef TINK_SIGNATURE_SIGNATURE_PEM_KEYSET_READER_H_
#define TINK_SIGNATURE_SIGNATURE_PEM_KEYSET_READER_H_

#include <utility>
#include <vector>

#include "tink/keyset_reader.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// Type of key. Currently, only RSA keys are supported.
// TODO(ambrosin): Add EC keys persing.
enum PemKeyType { PEM_RSA, PEM_EC };

// Algorithm to use with this key.
enum PemAlgorithm {
  RSASSA_PSS,
  RSASSA_PKCS1,
  ECDSA_IEEE  // Represents the NIST_P256 curve with IEEE_P1363 encoding
};

// Common set of parameters for the PEM key.
struct PemKeyParams {
  PemKeyType key_type;
  PemAlgorithm algorithm;
  size_t key_size_in_bits;
  ::google::crypto::tink::HashType hash_type;
};

// A PEM key consists of its serialized data `serialized_key`, and parameters
// `parameters`.
struct PemKey {
  std::string serialized_key;
  PemKeyParams parameters;
};

// Base class for parsing PEM-encoded keys (RFC 7468) into a keyset.
class SignaturePemKeysetReader : public KeysetReader {
 public:
  util::StatusOr<std::unique_ptr<::google::crypto::tink::EncryptedKeyset>>
  ReadEncrypted() override;

 protected:
  explicit SignaturePemKeysetReader(
      const std::vector<PemKey>& pem_serialized_keys)
      : pem_serialized_keys_(pem_serialized_keys) {}

  // PEM-serialized keys to parse.
  std::vector<PemKey> pem_serialized_keys_;
};

// Builder class for creating a PEM reader. Example usage:
//
// std::string some_public_key_pem = ...;
// PemKeyType key_type = ...;
// size_t key_size_in_bits = ...;
// HashType hash_type = ...;
// PemAlgorithm algorithm = ...;
//
// auto builder = SignaturePemKeysetReaderBuilder(
//     PemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
// builder.Add(
//     {.serialized_key = some_rsa_public_key_pem,
//      .parameters = {
//          .key_type = key_type,
//          .algorithm = algorithm,
//          .key_size_in_bits = key_size_in_bits,
//          .hash_type = hash_type}});
// ...
// auto reader_statusor = builder.Build();
// if (!reader_statusor.ok()) /* handle failure */
//
// auto keyset_handle_statusor =
//     CleartextKeysetHandle::Read(reader_statusor.ValueOrDie());
class SignaturePemKeysetReaderBuilder {
 public:
  // Type of reader to build. The builder type depends on the primitive
  // supported by the keys to parse.
  enum PemReaderType { PUBLIC_KEY_SIGN, PUBLIC_KEY_VERIFY };

  explicit SignaturePemKeysetReaderBuilder(PemReaderType pem_reader_type)
      : pem_reader_type_(pem_reader_type) {}

  // Adds a PEM serialized key `pem_serialized_key` to the builder.
  void Add(const PemKey& pem_serialized_key);

  // Creates an instance of keyset reader based on `pem_reader_type_`, to parse
  // the PEM-encoded keys in `pem_serialized_keys_`.
  util::StatusOr<std::unique_ptr<KeysetReader>> Build();

 private:
  // List of keys as PEM serialized items.
  std::vector<PemKey> pem_serialized_keys_;
  // Reader type that this reader must support.
  PemReaderType pem_reader_type_;
};

// Keyset reader for PEM keys that support the PublicKeySign principal.
class PublicKeySignPemKeysetReader : public SignaturePemKeysetReader {
 public:
  util::StatusOr<std::unique_ptr<::google::crypto::tink::Keyset>> Read()
      override;

 private:
  // Friend builder class.
  friend class SignaturePemKeysetReaderBuilder;

  explicit PublicKeySignPemKeysetReader(
      const std::vector<PemKey> pem_serialized_keys)
      : SignaturePemKeysetReader(pem_serialized_keys) {}
};

// Keyset reader for PEM keys that support the PublicKeyVerify principal.
class PublicKeyVerifyPemKeysetReader : public SignaturePemKeysetReader {
 public:
  util::StatusOr<std::unique_ptr<::google::crypto::tink::Keyset>> Read()
      override;

 private:
  // Friend builder class.
  friend class SignaturePemKeysetReaderBuilder;

  explicit PublicKeyVerifyPemKeysetReader(
      const std::vector<PemKey> pem_serialized_keys)
      : SignaturePemKeysetReader(pem_serialized_keys) {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_SIGNATURE_PEM_KEYSET_READER_H_
