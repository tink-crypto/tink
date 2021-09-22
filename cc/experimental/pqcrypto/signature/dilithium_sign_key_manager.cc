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

#include "tink/experimental/pqcrypto/signature/dilithium_sign_key_manager.h"

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/experimental/pqcrypto/signature/dilithium_verify_key_manager.h"
#include "tink/experimental/pqcrypto/signature/subtle/dilithium_avx2_sign.h"
#include "tink/experimental/pqcrypto/signature/subtle/dilithium_key.h"
#include "tink/experimental/pqcrypto/signature/util/enums.h"
#include "tink/public_key_sign.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/dilithium2/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium3/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium5/avx2/api.h"
}

namespace crypto {
namespace tink {

using ::crypto::tink::subtle::DilithiumPrivateKeyPqclean;
using ::crypto::tink::subtle::DilithiumPublicKeyPqclean;
using ::crypto::tink::util::EnumsPqcrypto;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::DilithiumKeyFormat;
using ::google::crypto::tink::DilithiumPrivateKey;
using ::google::crypto::tink::DilithiumPublicKey;

StatusOr<DilithiumPrivateKey> DilithiumSignKeyManager::CreateKey(
    const DilithiumKeyFormat& key_format) const {
  DilithiumPrivateKey dilithium_sk;
  dilithium_sk.set_version(get_version());

  DilithiumPublicKey* dilithium_pk = dilithium_sk.mutable_public_key();
  dilithium_pk->set_version(get_version());

  util::StatusOr<
      std::pair<DilithiumPrivateKeyPqclean, DilithiumPublicKeyPqclean>>
      key_pair = DilithiumPrivateKeyPqclean::GenerateKeyPair(
          key_format.params().key_size(),
          EnumsPqcrypto::ProtoToSubtle(key_format.params().seed_expansion()));
  if (!key_pair.status().ok()) {
    return key_pair.status();
  }

  dilithium_sk.set_key_value(
      util::SecretDataAsStringView(key_pair->first.GetKeyData()));
  dilithium_pk->set_key_value(key_pair->second.GetKeyData());
  *(dilithium_pk->mutable_params()) = key_format.params();

  return dilithium_sk;
}

StatusOr<std::unique_ptr<PublicKeySign>>
DilithiumSignKeyManager::PublicKeySignFactory::Create(
    const DilithiumPrivateKey& private_key) const {
  util::SecretData sk_data =
      util::SecretDataFromStringView(private_key.key_value());

  util::StatusOr<DilithiumPrivateKeyPqclean> dilithium_private_key =
      DilithiumPrivateKeyPqclean::NewPrivateKey(
          sk_data, EnumsPqcrypto::ProtoToSubtle(
                       private_key.public_key().params().seed_expansion()));

  if (!dilithium_private_key.ok()) return dilithium_private_key.status();

  return subtle::DilithiumAvx2Sign::New(*dilithium_private_key);
}

Status DilithiumSignKeyManager::ValidateKey(
    const DilithiumPrivateKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (key.key_value().length() !=
          PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES &&
      key.key_value().length() !=
          PQCLEAN_DILITHIUM3_AVX2_CRYPTO_SECRETKEYBYTES &&
      key.key_value().length() !=
          PQCLEAN_DILITHIUM5_AVX2_CRYPTO_SECRETKEYBYTES) {
    return Status(util::error::INVALID_ARGUMENT,
                  "Invalid dilithium private key size.");
  }

  return util::OkStatus();
}

Status DilithiumSignKeyManager::ValidateKeyFormat(
    const DilithiumKeyFormat& key_format) const {
  if (!key_format.has_params()) {
    return Status(util::error::INVALID_ARGUMENT, "Missing params.");
  }

  return DilithiumVerifyKeyManager().ValidateParams(key_format.params());
}

}  // namespace tink
}  // namespace crypto
