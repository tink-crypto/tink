// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/subtle/prf/hkdf_streaming_prf.h"

#include <algorithm>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "tink/internal/md_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {

class HkdfInputStream : public InputStream {
 public:
  HkdfInputStream(const EVP_MD *digest, const util::SecretData &secret,
                  absl::string_view salt, absl::string_view input)
      : input_(input) {
    stream_status_ = Init(digest, secret, salt);
  }

  crypto::tink::util::StatusOr<int> Next(const void **data) override {
    if (!stream_status_.ok()) {
      return stream_status_;
    }
    if (position_in_ti_ < ti_.size()) {
      return returnDataFromPosition(data);
    }
    if (i_ == 255) {
      stream_status_ =
          crypto::tink::util::Status(absl::StatusCode::kOutOfRange, "EOF");
      return stream_status_;
    }
    stream_status_ = UpdateTi();
    if (!stream_status_.ok()) {
      return stream_status_;
    }
    return returnDataFromPosition(data);
  }

  void BackUp(int count) override {
    position_in_ti_ -= std::min(std::max(0, count), position_in_ti_);
  }

  int64_t Position() const override {
    if (i_ == 0) return 0;
    return (i_ - 1) * ti_.size() + position_in_ti_;
  }

 private:
  util::Status Init(const EVP_MD *digest, const util::SecretData &secret,
                    absl::string_view salt) {
    // PRK as by RFC 5869, Section 2.2
    util::SecretData prk(EVP_MAX_MD_SIZE);

    if (!digest) {
      return util::Status(absl::StatusCode::kInvalidArgument, "Invalid digest");
    }
    const size_t digest_size = EVP_MD_size(digest);
    if (digest_size == 0) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid digest size (0)");
    }
    ti_.resize(digest_size);

    // BoringSSL's `HDKF_extract` function is implemented as an HMAC [1]. We
    // replace calls to `HDKF_extract` with a direct call to `HMAC` to make this
    // compatible to OpenSSL, which doesn't expose `HKDF*` functions.
    //
    // [1] https://github.com/google/boringssl/blob/master/crypto/hkdf/hkdf.c#L42
    unsigned prk_len;
    if (HMAC(digest, reinterpret_cast<const uint8_t *>(salt.data()),
             salt.size(), secret.data(), secret.size(), prk.data(),
             &prk_len) == nullptr ||
        prk_len != digest_size) {
      return util::Status(absl::StatusCode::kInternal, "HKDF-Extract failed");
    }
    prk.resize(prk_len);
    if (!hmac_ctx_) {
      return util::Status(absl::StatusCode::kInternal, "HMAC_CTX_new failed");
    }
    if (!HMAC_Init_ex(hmac_ctx_.get(), prk.data(), prk.size(), digest,
                      nullptr)) {
      return util::Status(absl::StatusCode::kInternal, "HMAC_Init_ex failed");
    }
    return UpdateTi();
  }

  int returnDataFromPosition(const void **data) {
    // There's still data in ti to return.
    *data = ti_.data() + position_in_ti_;
    int result = ti_.size() - position_in_ti_;
    position_in_ti_ = ti_.size();
    return result;
  }

  // Sets T(i+i) = HMAC-Hash(PRK, T(i) | info | i + 1) as in RFC 5869,
  // Section 2.3
  // Unfortunately, boringSSL does not provide a function which updates T(i)
  // for a single round; hence we implement this ourselves.
  util::Status UpdateTi() {
    if (!HMAC_Init_ex(hmac_ctx_.get(), nullptr, 0, nullptr, nullptr)) {
      return util::Status(absl::StatusCode::kInternal, "HMAC_Init_ex failed");
    }
    if (i_ != 0 && !HMAC_Update(hmac_ctx_.get(), ti_.data(), ti_.size())) {
      return util::Status(absl::StatusCode::kInternal,
                          "HMAC_Update failed on ti_");
    }
    if (!HMAC_Update(hmac_ctx_.get(),
                     reinterpret_cast<const uint8_t *>(&input_[0]),
                     input_.size())) {
      return util::Status(absl::StatusCode::kInternal,
                          "HMAC_Update failed on input_");
    }
    uint8_t i_as_uint8 = i_ + 1;
    if (!HMAC_Update(hmac_ctx_.get(), &i_as_uint8, 1)) {
      return util::Status(absl::StatusCode::kInternal,
                          "HMAC_Update failed on i_");
    }
    if (!HMAC_Final(hmac_ctx_.get(), ti_.data(), nullptr)) {
      return util::Status(absl::StatusCode::kInternal, "HMAC_Final failed");
    }
    i_++;
    position_in_ti_ = 0;
    return util::OkStatus();
  }

  // OUT_OF_RANGE_ERROR in case we returned all the data. Other errors indicate
  // problems and are permanent.
  util::Status stream_status_ = util::OkStatus();

  internal::SslUniquePtr<HMAC_CTX> hmac_ctx_{HMAC_CTX_new()};

  // Current value T(i).
  util::SecretData ti_;
  // By RFC 5869: 0 <= i_ <= 255*HashLen
  int i_ = 0;

  std::string input_;

  // The current position of ti which we returned.
  int position_in_ti_ = 0;
};

}  // namespace

std::unique_ptr<InputStream> HkdfStreamingPrf::ComputePrf(
    absl::string_view input) const {
  return absl::make_unique<HkdfInputStream>(hash_, secret_, salt_, input);
}

// static
crypto::tink::util::StatusOr<std::unique_ptr<StreamingPrf>>
HkdfStreamingPrf::New(HashType hash, util::SecretData secret,
                      absl::string_view salt) {
  auto status = internal::CheckFipsCompatibility<HkdfStreamingPrf>();
  if (!status.ok()) return status;

  if (hash != SHA256 && hash != SHA512 && hash != SHA1) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Hash ", hash, " not acceptable for HkdfStreamingPrf"));
  }

  if (secret.size() < 10) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Too short secret for HkdfStreamingPrf");
  }
  util::StatusOr<const EVP_MD *> evp_md = internal::EvpHashFromHashType(hash);
  if (!evp_md.ok()) {
    return util::Status(absl::StatusCode::kUnimplemented, "Unsupported hash");
  }

  return {
      absl::WrapUnique(new HkdfStreamingPrf(*evp_md, std::move(secret), salt))};
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
