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

package com.google.crypto.tink.testing;

import com.google.crypto.tink.subtle.Hex;

/** Test utility class containing test vectors from the HPKE I.-D. */
public final class HpkeTestUtil {
  /** Helper class that contains individual test vector fields. */
  public static class TestVector {
    public byte[] recipientPublicKey; // pkRm
    public byte[] encapsulatedKey; // enc
    public byte[] sharedSecret; // shared_secret
    public byte[] senderPrivateKey; // skEm
    public byte[] recipientPrivateKey; // skRm

    public TestVector(
        String recipientPublicKey,
        String encapsulatedKey,
        String sharedSecret,
        String senderPrivateKey,
        String recipientPrivateKey) {
      this.recipientPublicKey = Hex.decode(recipientPublicKey);
      this.encapsulatedKey = Hex.decode(encapsulatedKey);
      this.sharedSecret = Hex.decode(sharedSecret);
      this.senderPrivateKey = Hex.decode(senderPrivateKey);
      this.recipientPrivateKey = Hex.decode(recipientPrivateKey);
    }
  }

  // Test vector for DHKEM(X25519, HKDF-SHA256),HKDF-SHA256, AES-128-GCM
  // https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-11.html#appendix-A.1
  public static final TestVector X25519_HKDF_SHA256_AES_128_GCM_TEST =
      new TestVector(
          "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d", // pkRm
          "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431", // enc
          "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc", // shared_secret
          "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736", // skEm
          "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8" // skRm
          );

  // Test vector for DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
  // https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-11.html#appendix-A.2
  public static final TestVector X25519_HKDF_SHA256_CHACHAPOLY1305_TEST =
      new TestVector(
          "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a", // pkRm
          "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a", // enc
          "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7", // shared_secret
          "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600", // skEm
          "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb" // skRm
          );

  // Test vector for DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, Export-Only AEAD
  // https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-11.html#appendix-A.7
  public static final TestVector X25519_HKDF_SHA256_EXPORT_ONLY_AEAD_TEST =
      new TestVector(
          "194141ca6c3c3beb4792cd97ba0ea1faff09d98435012345766ee33aae2d7664", // pkRm
          "e5e8f9bfff6c2f29791fc351d2c25ce1299aa5eaca78a757c0b4fb4bcd830918", // enc
          "e81716ce8f73141d4f25ee9098efc968c91e5b8ce52ffff59d64039e82918b66", // shared_secret
          "095182b502f1f91f63ba584c7c3ec473d617b8b4c2cec3fad5af7fa6748165ed", // skEm
          "33d196c830a12f9ac65d6e565a590d80f04ee9b19c83c87f2c170d972a812848" // skRm
          );

  private HpkeTestUtil() {}
}
