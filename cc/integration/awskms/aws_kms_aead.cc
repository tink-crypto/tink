// Copyright 2018 Google LLC
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

#include "tink/integration/awskms/aws_kms_aead.h"

#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "aws/core/auth/AWSCredentialsProvider.h"
#include "aws/core/client/AWSClient.h"
#include "aws/core/utils/Outcome.h"
#include "aws/core/utils/memory/AWSMemory.h"
#include "aws/kms/KMSClient.h"
#include "aws/kms/KMSErrors.h"
#include "aws/kms/model/DecryptRequest.h"
#include "aws/kms/model/DecryptResult.h"
#include "aws/kms/model/EncryptRequest.h"
#include "aws/kms/model/EncryptResult.h"
#include "tink/aead.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace integration {
namespace awskms {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

namespace {

// TODO: pull out hex-helpers from test_util and remove the copy below.
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

std::string AwsErrorToString(Aws::Client::AWSError<Aws::KMS::KMSErrors> err) {
  return absl::StrCat("AWS error code: ", err.GetErrorType(), ", ",
                      err.GetExceptionName(), ": ", err.GetMessage());
}

}  // namespace

AwsKmsAead::AwsKmsAead(absl::string_view key_arn,
                       std::shared_ptr<Aws::KMS::KMSClient> aws_client) :
    key_arn_(key_arn), aws_client_(aws_client) {
}

// static
StatusOr<std::unique_ptr<Aead>>
AwsKmsAead::New(absl::string_view key_arn,
                std::shared_ptr<Aws::KMS::KMSClient> aws_client) {
  if (key_arn.empty()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Key ARN cannot be empty.");
  }
  if (aws_client == nullptr) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "AWS KMS client cannot be null.");
  }
  std::unique_ptr<Aead> aead(new AwsKmsAead(key_arn, aws_client));
  return std::move(aead);
}

StatusOr<std::string> AwsKmsAead::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data) const {
  Aws::KMS::Model::EncryptRequest req;
  req.SetKeyId(key_arn_.c_str());
  Aws::Utils::ByteBuffer plaintext_buffer(
      reinterpret_cast<const unsigned char*>(plaintext.data()),
      plaintext.length());
  req.SetPlaintext(plaintext_buffer);
  if (!associated_data.empty()) {
    req.AddEncryptionContext("associatedData",
                             HexEncode(associated_data).c_str());
  }
  auto outcome = aws_client_->Encrypt(req);
  if (outcome.IsSuccess()) {
    auto& blob = outcome.GetResult().GetCiphertextBlob();
    std::string ciphertext(
        reinterpret_cast<const char*>(blob.GetUnderlyingData()),
        blob.GetLength());
    return ciphertext;
  }
  auto& err = outcome.GetError();
  return ToStatusF(absl::StatusCode::kInvalidArgument,
                   "AWS KMS encryption failed with error: %s",
                   AwsErrorToString(err));
}

StatusOr<std::string> AwsKmsAead::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data) const {
  Aws::KMS::Model::DecryptRequest req;
  req.SetKeyId(key_arn_.c_str());
  Aws::Utils::ByteBuffer ciphertext_buffer(
      reinterpret_cast<const unsigned char*>(ciphertext.data()),
      ciphertext.length());
  req.SetCiphertextBlob(ciphertext_buffer);
  if (!associated_data.empty()) {
    req.AddEncryptionContext("associatedData",
                             HexEncode(associated_data).c_str());
  }
  auto outcome = aws_client_->Decrypt(req);
  if (outcome.IsSuccess()) {
    if (outcome.GetResult().GetKeyId() != Aws::String(key_arn_.c_str())) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "AWS KMS decryption failed: wrong key ARN.");
    }
    auto& buffer = outcome.GetResult().GetPlaintext();
    std::string plaintext(
        reinterpret_cast<const char*>(buffer.GetUnderlyingData()),
        buffer.GetLength());
    return plaintext;
  }
  auto& err = outcome.GetError();
  return ToStatusF(absl::StatusCode::kInvalidArgument,
                   "AWS KMS decryption failed with error: %s",
                   AwsErrorToString(err));
}

}  // namespace awskms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
