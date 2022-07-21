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

#include "tink/experimental/pqcrypto/signature/sphincs_key_template.h"

#include "tink/util/constants.h"
#include "proto/experimental/pqcrypto/sphincs.pb.h"
#include "proto/tink.pb.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256s-simple/api.h"
}

namespace crypto {
namespace tink {
namespace {

using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::SphincsHashType;
using ::google::crypto::tink::SphincsKeyFormat;
using ::google::crypto::tink::SphincsParams;
using ::google::crypto::tink::SphincsPrivateKey;
using ::google::crypto::tink::SphincsSignatureType;
using ::google::crypto::tink::SphincsVariant;

KeyTemplate* NewSphincsKeyTemplate(int32 private_key_size,
                                   SphincsHashType hash_type,
                                   SphincsVariant variant,
                                   SphincsSignatureType type) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      absl::StrCat(kTypeGoogleapisCom, SphincsPrivateKey().GetTypeName()));
  key_template->set_output_prefix_type(OutputPrefixType::TINK);

  SphincsKeyFormat key_format;
  SphincsParams* params = key_format.mutable_params();
  params->set_key_size(private_key_size);
  params->set_hash_type(hash_type);
  params->set_variant(variant);
  params->set_sig_length_type(type);
  key_format.SerializeToString(key_template->mutable_value());

  return key_template;
}

}  // anonymous namespace

// HARAKA
const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_128_F_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSHARAKA128FROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::HARAKA, SphincsVariant::ROBUST,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_128_F_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSHARAKA128FSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::HARAKA, SphincsVariant::SIMPLE,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_128_S_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSHARAKA128SROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::HARAKA, SphincsVariant::ROBUST,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_128_S_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSHARAKA128SSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::HARAKA, SphincsVariant::SIMPLE,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_192_F_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSHARAKA192FROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::HARAKA, SphincsVariant::ROBUST,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_192_F_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSHARAKA192FSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::HARAKA, SphincsVariant::SIMPLE,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_192_S_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSHARAKA192SROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::HARAKA, SphincsVariant::ROBUST,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_192_S_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSHARAKA192SSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::HARAKA, SphincsVariant::SIMPLE,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_256_F_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSHARAKA256FROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::HARAKA, SphincsVariant::ROBUST,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_256_F_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSHARAKA256FSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::HARAKA, SphincsVariant::SIMPLE,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_256_S_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSHARAKA256SROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::HARAKA, SphincsVariant::ROBUST,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_256_S_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSHARAKA256SSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::HARAKA, SphincsVariant::SIMPLE,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

// SHA256
const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_128_F_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHA256128FROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHA256, SphincsVariant::ROBUST,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_128_F_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHA256128FSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHA256, SphincsVariant::SIMPLE,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_128_S_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHA256128SROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHA256, SphincsVariant::ROBUST,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_128_S_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHA256128SSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHA256, SphincsVariant::SIMPLE,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_192_F_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHA256192FROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHA256, SphincsVariant::ROBUST,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_192_F_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHA256192FSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHA256, SphincsVariant::SIMPLE,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_192_S_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHA256192SROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHA256, SphincsVariant::ROBUST,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_192_S_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHA256192SSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHA256, SphincsVariant::SIMPLE,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_256_F_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHA256256FROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHA256, SphincsVariant::ROBUST,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_256_F_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHA256256FSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHA256, SphincsVariant::SIMPLE,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_256_S_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHA256256SROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHA256, SphincsVariant::ROBUST,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_256_S_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHA256256SSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHA256, SphincsVariant::SIMPLE,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

// SHAKE256
const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_128_F_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHAKE256128FROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHAKE256, SphincsVariant::ROBUST,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_128_F_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHAKE256, SphincsVariant::SIMPLE,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_128_S_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHAKE256128SROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHAKE256, SphincsVariant::ROBUST,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_128_S_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHAKE256, SphincsVariant::SIMPLE,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_192_F_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHAKE256192FROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHAKE256, SphincsVariant::ROBUST,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_192_F_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHAKE256, SphincsVariant::SIMPLE,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_192_S_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHAKE256192SROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHAKE256, SphincsVariant::ROBUST,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_192_S_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHAKE256, SphincsVariant::SIMPLE,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_256_F_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHAKE256256FROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHAKE256, SphincsVariant::ROBUST,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_256_F_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHAKE256, SphincsVariant::SIMPLE,
      SphincsSignatureType::FAST_SIGNING);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_256_S_Robust_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHAKE256256SROBUST_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHAKE256, SphincsVariant::ROBUST,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_256_S_Simple_KeyTemplate() {
  static const KeyTemplate* key_template = NewSphincsKeyTemplate(
      PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CRYPTO_SECRETKEYBYTES,
      SphincsHashType::SHAKE256, SphincsVariant::SIMPLE,
      SphincsSignatureType::SMALL_SIGNATURE);
  return *key_template;
}

}  // namespace tink
}  // namespace crypto
