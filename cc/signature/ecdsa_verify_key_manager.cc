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

#include "tink/signature/ecdsa_verify_key_manager.h"

#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/ec_util.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/ecdsa.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Enums;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::EcdsaParams;
using google::crypto::tink::EcdsaPublicKey;
using google::crypto::tink::EcdsaSignatureEncoding;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;

StatusOr<std::unique_ptr<PublicKeyVerify>>
EcdsaVerifyKeyManager::PublicKeyVerifyFactory::Create(
    const EcdsaPublicKey& ecdsa_public_key) const {
  internal::EcKey ec_key;
  ec_key.curve = Enums::ProtoToSubtle(ecdsa_public_key.params().curve());
  ec_key.pub_x = ecdsa_public_key.x();
  ec_key.pub_y = ecdsa_public_key.y();
  auto result = subtle::EcdsaVerifyBoringSsl::New(
      ec_key, Enums::ProtoToSubtle(ecdsa_public_key.params().hash_type()),
      Enums::ProtoToSubtle(ecdsa_public_key.params().encoding()));
  if (!result.ok()) return result.status();
  return {std::move(result.value())};
}

Status EcdsaVerifyKeyManager::ValidateParams(const EcdsaParams& params) const {
  switch (params.encoding()) {
    case EcdsaSignatureEncoding::DER:  // fall through
    case EcdsaSignatureEncoding::IEEE_P1363:
      break;
    default:
      return ToStatusF(absl::StatusCode::kInvalidArgument,
                       "Unsupported signature encoding: %d", params.encoding());
  }
  switch (params.curve()) {
    case EllipticCurveType::NIST_P256:
      // Using SHA512 for curve P256 is fine. However, only the 256
      // leftmost bits of the hash is used in signature computation.
      // Therefore, we don't allow it here to prevent security illusion.
      if (params.hash_type() != HashType::SHA256) {
        return Status(absl::StatusCode::kInvalidArgument,
                      "Only SHA256 is supported for NIST P256.");
      }
      break;
    case EllipticCurveType::NIST_P384:
      // Allow using SHA384 and SHA512 with NIST-P384.
      if ((params.hash_type() != HashType::SHA384) &&
          (params.hash_type() != HashType::SHA512)) {
        return Status(absl::StatusCode::kInvalidArgument,
                      "Only SHA384 and SHA512 are supported for this curve.");
      }
      break;
    case EllipticCurveType::NIST_P521:
      if (params.hash_type() != HashType::SHA512) {
        return Status(absl::StatusCode::kInvalidArgument,
                      "Only SHA512 is supported for this curve.");
      }
      break;
    default:
      return Status(absl::StatusCode::kInvalidArgument,
                    "Unsupported elliptic curve");
  }
  return util::OkStatus();
}

Status EcdsaVerifyKeyManager::ValidateKey(const EcdsaPublicKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  return ValidateParams(key.params());
}

}  // namespace tink
}  // namespace crypto
