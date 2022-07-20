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

package com.google.crypto.tink.hybrid.internal;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.io.Files;
import com.google.common.truth.Expect;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.HpkePrivateKey;
import com.google.crypto.tink.proto.HpkePublicKey;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.HpkeTestEncryption;
import com.google.crypto.tink.testing.HpkeTestId;
import com.google.crypto.tink.testing.HpkeTestSetup;
import com.google.crypto.tink.testing.HpkeTestUtil;
import com.google.crypto.tink.testing.HpkeTestVector;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link HpkeContext}. */
@RunWith(JUnit4.class)
public final class HpkeContextTest {
  private static Map<HpkeTestId, HpkeTestVector> testVectors;

  @Rule public final Expect expect = Expect.create();

  @BeforeClass
  public static void setUpTestVectors() throws IOException {
    String path = "testdata/testvectors/hpke_boringssl.json";
    if (TestUtil.isAndroid()) {
      path = "/sdcard/googletest/test_runfiles/google3/" + path; // Special prefix for Android.
    }
    testVectors = HpkeTestUtil.parseTestVectors(Files.newReader(new File(path), UTF_8));
  }

  private HpkeTestVector getTestVector(byte[] mode, byte[] kemId, byte[] kdfId, byte[] aeadId) {
    HpkeTestId testId = new HpkeTestId(mode, kemId, kdfId, aeadId);
    return testVectors.get(testId);
  }

  private void verifyContext(HpkeContext context, HpkeTestVector testVector) {
    HpkeTestSetup testSetup = testVector.getTestSetup();
    expect.that(context.getKey()).isEqualTo(testSetup.key);
    expect.that(context.getBaseNonce()).isEqualTo(testSetup.baseNonce);
  }

  private void verifyEncrypt(HpkeContext context, HpkeTestVector testVector)
      throws GeneralSecurityException {
    expect.that(testVector.getEncryptions().size()).isGreaterThan(10);
    for (int i = 0; i < 10; ++i) {
      HpkeTestEncryption encryption = testVector.getEncryptions().get(i);
      expect.that(encryption.sequenceNumber.intValue()).isEqualTo(i);
      expect
          .that(context.seal(encryption.plaintext, encryption.associatedData))
          .isEqualTo(encryption.ciphertext);
    }
  }

  private void verifyDecrypt(HpkeContext context, HpkeTestVector testVector)
      throws GeneralSecurityException {
    expect.that(testVector.getEncryptions().size()).isGreaterThan(10);
    for (int i = 0; i < 10; ++i) {
      HpkeTestEncryption encryption = testVector.getEncryptions().get(i);
      expect.that(encryption.sequenceNumber.intValue()).isEqualTo(i);
      expect
          .that(context.open(encryption.ciphertext, encryption.associatedData))
          .isEqualTo(encryption.plaintext);
    }
  }

  /** Helper method to verify context against test vectors provided in HPKE I.-D. */
  private void testContext(byte[] mode, byte[] kemId, byte[] kdfId, byte[] aeadId)
      throws GeneralSecurityException {
    HpkeTestVector testVector = getTestVector(mode, kemId, kdfId, aeadId);
    HpkeTestSetup testSetup = testVector.getTestSetup();

    HpkeKem kem = HpkePrimitiveFactory.createKem(kemId);
    HpkeKdf kdf = HpkePrimitiveFactory.createKdf(kdfId);
    HpkeAead aead = HpkePrimitiveFactory.createAead(aeadId);

    HpkeContext encryptionContext =
        HpkeContext.createContext(
            testSetup.encapsulatedKey, testSetup.sharedSecret, kem, kdf, aead, testSetup.info);
    verifyContext(encryptionContext, testVector);
    verifyEncrypt(encryptionContext, testVector);

    HpkeContext decryptionContext =
        HpkeContext.createContext(
            testSetup.encapsulatedKey, testSetup.sharedSecret, kem, kdf, aead, testSetup.info);
    verifyContext(decryptionContext, testVector);
    verifyDecrypt(decryptionContext, testVector);
  }

  /** Helper method to verify context API provided to Tink users. */
  private void testSenderAndRecipientContexts(
      byte[] mode, byte[] kemId, byte[] kdfId, byte[] aeadId) throws GeneralSecurityException {
    HpkeTestVector testVector = getTestVector(mode, kemId, kdfId, aeadId);
    HpkeTestSetup testSetup = testVector.getTestSetup();

    HpkeKem kem = HpkePrimitiveFactory.createKem(kemId);
    HpkeKdf kdf = HpkePrimitiveFactory.createKdf(kdfId);
    HpkeAead aead = HpkePrimitiveFactory.createAead(aeadId);

    HpkePublicKey recipientPublicKey =
        HpkePublicKey.newBuilder()
            .setPublicKey(ByteString.copyFrom(testSetup.recipientPublicKey))
            .build();
    HpkePrivateKey recipientPrivateKey =
        HpkePrivateKey.newBuilder()
            .setPrivateKey(ByteString.copyFrom(testSetup.recipientPrivateKey))
            .setPublicKey(
                HpkePublicKey.newBuilder()
                    .setParams(
                        HpkeParams.newBuilder()
                            .setKem(com.google.crypto.tink.proto.HpkeKem.DHKEM_X25519_HKDF_SHA256)
                            .build())
                    .build())
            .build();

    HpkeContext senderContext =
        HpkeContext.createSenderContext(recipientPublicKey, kem, kdf, aead, testSetup.info);

    HpkeKemPrivateKey recipientKemPrivateKey = HpkeKemKeyFactory.createPrivate(recipientPrivateKey);
    HpkeContext recipientContext =
        HpkeContext.createRecipientContext(
            senderContext.getEncapsulatedKey(),
            recipientKemPrivateKey,
            kem,
            kdf,
            aead,
            testSetup.info);

    byte[] plaintext = Random.randBytes(200);
    byte[] aad = Random.randBytes(100);
    byte[] ciphertext = senderContext.seal(plaintext, aad);
    expect.that(recipientContext.open(ciphertext, aad)).isEqualTo(plaintext);
  }

  @Test
  public void createContext_succeedsWithX25519HkdfSha256Aes128Gcm()
      throws GeneralSecurityException {
    testContext(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_128_GCM_AEAD_ID);
  }

  @Test
  public void createSenderAndRecipientContexts_succeedsWithX25519HkdfSha256Aes128Gcm()
      throws GeneralSecurityException {
    testSenderAndRecipientContexts(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_128_GCM_AEAD_ID);
  }

  @Test
  public void createContext_succeedsWithX25519HkdfSha256Aes256Gcm()
      throws GeneralSecurityException {
    testContext(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_256_GCM_AEAD_ID);
  }

  @Test
  public void createSenderAndRecipientContexts_succeedsWithX25519HkdfSha256Aes256Gcm()
      throws GeneralSecurityException {
    testSenderAndRecipientContexts(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_256_GCM_AEAD_ID);
  }
}
