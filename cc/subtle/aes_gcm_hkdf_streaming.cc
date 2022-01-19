// Copyright 2019 Google Inc.
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

#include "tink/subtle/aes_gcm_hkdf_streaming.h"

#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/subtle/aes_gcm_hkdf_stream_segment_decrypter.h"
#include "tink/subtle/aes_gcm_hkdf_stream_segment_encrypter.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/subtle/random.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {
util::Status Validate(const AesGcmHkdfStreaming::Params& params) {
  if (!(params.hkdf_hash == SHA1 || params.hkdf_hash == SHA256 ||
        params.hkdf_hash == SHA512)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "unsupported hkdf_hash");
  }
  if (params.ikm.size() < 16 || params.ikm.size() < params.derived_key_size) {
    return util::Status(absl::StatusCode::kInvalidArgument, "ikm too small");
  }
  if (params.derived_key_size != 16 && params.derived_key_size != 32) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "derived_key_size must be 16 or 32");
  }
  if (params.ciphertext_offset < 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext_offset must be non-negative");
  }
  if (params.ciphertext_segment_size <=
      params.ciphertext_offset + params.derived_key_size +
          AesGcmHkdfStreamSegmentEncrypter::kTagSizeInBytes) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext_segment_size too small");
  }
  return util::OkStatus();
}
}  // namespace

util::StatusOr<std::unique_ptr<AesGcmHkdfStreaming>> AesGcmHkdfStreaming::New(
    Params params) {
  auto status = internal::CheckFipsCompatibility<AesGcmHkdfStreaming>();
  if (!status.ok()) return status;

  status = Validate(params);
  if (!status.ok()) return status;
  return {absl::WrapUnique(new AesGcmHkdfStreaming(std::move(params)))};
}

util::StatusOr<std::unique_ptr<StreamSegmentEncrypter>>
AesGcmHkdfStreaming::NewSegmentEncrypter(
    absl::string_view associated_data) const {
  AesGcmHkdfStreamSegmentEncrypter::Params params;
  params.salt = Random::GetRandomBytes(derived_key_size_);
  auto hkdf_result = Hkdf::ComputeHkdf(hkdf_hash_, ikm_, params.salt,
                                       associated_data, derived_key_size_);
  if (!hkdf_result.ok()) return hkdf_result.status();
  params.key = std::move(hkdf_result).ValueOrDie();
  params.ciphertext_offset = ciphertext_offset_;
  params.ciphertext_segment_size = ciphertext_segment_size_;
  return AesGcmHkdfStreamSegmentEncrypter::New(std::move(params));
}

util::StatusOr<std::unique_ptr<StreamSegmentDecrypter>>
AesGcmHkdfStreaming::NewSegmentDecrypter(
    absl::string_view associated_data) const {
  AesGcmHkdfStreamSegmentDecrypter::Params params;
  params.ikm = ikm_;
  params.hkdf_hash = hkdf_hash_;
  params.derived_key_size = derived_key_size_;
  params.ciphertext_offset = ciphertext_offset_;
  params.ciphertext_segment_size = ciphertext_segment_size_;
  params.associated_data = std::string(associated_data);
  return AesGcmHkdfStreamSegmentDecrypter::New(std::move(params));
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
