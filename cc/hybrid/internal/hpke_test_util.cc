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

#include "tink/hybrid/internal/hpke_test_util.h"

#include <string>

#include "absl/status/status.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/util/status.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {

// Test vector from https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
const absl::string_view kTestX25519HkdfSha256Aes128Gcm[] = {
    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",  // pkRm
    "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",  // skEm
    "4f6465206f6e2061204772656369616e2055726e",                          // info
    "4265617574792069732074727574682c20747275746820626561757479",        // pt
    "436f756e742d30",                                                    // aad
    "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83"
    "d07bea87e13c512a",                                                  // ct
    "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",  // skRm
    "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"   // enc
};

// Test vector from https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.2.
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
const absl::string_view kTestX25519HkdfSha256ChaCha20Poly1305[] = {
    "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",  // pkRm
    "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",  // skEm
    "4f6465206f6e2061204772656369616e2055726e",                          // info
    "4265617574792069732074727574682c20747275746820626561757479",        // pt
    "436f756e742d30",                                                    // aad
    "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c"
    "62ce81883d2dd1b51a28",                                              // ct
    "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",  // skRm
    "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"   // enc
};

// BoringSSL test vectors with aead_id = 2.  Missing 'skRm' and 'enc'.
// (No test vectors provided by RFC 9180 for this test case).
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM
const absl::string_view kTestX25519HkdfSha256Aes256Gcm[] = {
    "ac66bae9ffa270cf4a89ed9f274e30c0456babae2572aaaf002ff0d8884ab018",  // pkRm
    "28e212563a8b6f068af7ff17400ff1baf23612b7a738bbaf5dfb321b2b5b431a",  // skEm
    "4f6465206f6e2061204772656369616e2055726e",                          // info
    "4265617574792069732074727574682c20747275746820626561757479",        // pt
    "436f756e742d30",                                                    // aad
    "23ded2d5d90ea89d975dac4792b297240f194952d7421aacbff0474100052b6bb8aa58d1"
    "8ef6c42b6960e2e28f",  // ct
    "",                    // Missing skRm
    "",                    // Missing enc
};

HpkeTestParams DefaultHpkeTestParams() {
  return HpkeTestParams(kTestX25519HkdfSha256Aes128Gcm);
}

util::StatusOr<HpkeTestParams> CreateHpkeTestParams(
    const google::crypto::tink::HpkeParams& params) {
  if (params.kem() != google::crypto::tink::HpkeKem::DHKEM_X25519_HKDF_SHA256) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("No test parameters for specified KEM:", params.kem()));
  }
  if (params.kdf() != google::crypto::tink::HpkeKdf::HKDF_SHA256) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("No test parameters for specified KDF:", params.kdf()));
  }
  switch (params.aead()) {
    case google::crypto::tink::HpkeAead::AES_128_GCM:
      return HpkeTestParams(kTestX25519HkdfSha256Aes128Gcm);
    case google::crypto::tink::HpkeAead::AES_256_GCM:
      return HpkeTestParams(kTestX25519HkdfSha256Aes256Gcm);
    case google::crypto::tink::HpkeAead::CHACHA20_POLY1305:
      return HpkeTestParams(kTestX25519HkdfSha256ChaCha20Poly1305);
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("No test parameters for specified AEAD:",
                                       params.aead()));
  }
}

util::StatusOr<HpkeTestParams> CreateHpkeTestParams(const HpkeParams& params) {
  if (params.kem != HpkeKem::kX25519HkdfSha256) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("No test parameters for specified KEM:", params.kem));
  }
  if (params.kdf != HpkeKdf::kHkdfSha256) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("No test parameters for specified KDF:", params.kdf));
  }
  switch (params.aead) {
    case HpkeAead::kAes128Gcm:
      return HpkeTestParams(kTestX25519HkdfSha256Aes128Gcm);
    case HpkeAead::kAes256Gcm:
      return HpkeTestParams(kTestX25519HkdfSha256Aes256Gcm);
    case HpkeAead::kChaCha20Poly1305:
      return HpkeTestParams(kTestX25519HkdfSha256ChaCha20Poly1305);
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("No test parameters for specified AEAD:", params.aead));
  }
}

google::crypto::tink::HpkeParams CreateHpkeParams(
    const google::crypto::tink::HpkeKem& kem,
    const google::crypto::tink::HpkeKdf& kdf,
    const google::crypto::tink::HpkeAead& aead) {
  google::crypto::tink::HpkeParams params;
  params.set_kem(kem);
  params.set_kdf(kdf);
  params.set_aead(aead);
  return params;
}

google::crypto::tink::HpkePublicKey CreateHpkePublicKey(
    const google::crypto::tink::HpkeParams& params,
    const std::string& raw_key_bytes) {
  google::crypto::tink::HpkePublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_public_key(raw_key_bytes);
  *key_proto.mutable_params() = params;
  return key_proto;
}

google::crypto::tink::HpkePrivateKey CreateHpkePrivateKey(
    const google::crypto::tink::HpkeParams& params,
    const std::string& raw_key_bytes) {
  google::crypto::tink::HpkePrivateKey private_key_proto;
  private_key_proto.set_version(0);
  private_key_proto.set_private_key(raw_key_bytes);
  google::crypto::tink::HpkePublicKey* public_key_proto =
      private_key_proto.mutable_public_key();
  *public_key_proto->mutable_params() = params;
  return private_key_proto;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
