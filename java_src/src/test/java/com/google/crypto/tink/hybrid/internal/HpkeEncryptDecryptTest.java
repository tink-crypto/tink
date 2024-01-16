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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.common.truth.Expect;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.hybrid.internal.testing.HpkeTestUtil;
import com.google.crypto.tink.hybrid.internal.testing.HybridTestVector;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.X25519;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link HpkeEncrypt} and {@link HpkeDecrypt}. */
@RunWith(Theories.class)
public final class HpkeEncryptDecryptTest {
  private static byte[] privateKeyBytes;
  private static byte[] publicKeyBytes;

  @Rule public final Expect expect = Expect.create();

  @BeforeClass
  public static void generateKeyMaterial() throws GeneralSecurityException {
    privateKeyBytes = X25519.generatePrivateKey();
    publicKeyBytes = X25519.publicFromPrivate(privateKeyBytes);
  }

  private HpkeParameters getDefaultValidParams() throws GeneralSecurityException {
    return HpkeParameters.builder()
        .setVariant(HpkeParameters.Variant.NO_PREFIX)
        .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
        .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
        .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
        .build();
  }

  private HpkePublicKey getPublicKey(HpkeParameters parameters) throws GeneralSecurityException {
    return HpkePublicKey.create(
        parameters, Bytes.copyFrom(publicKeyBytes), /* idRequirement= */ null);
  }

  private HpkePrivateKey getPrivateKey(HpkePublicKey publicKey) throws GeneralSecurityException {
    return HpkePrivateKey.create(
        publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void encryptDecrypt_succeedsWithX25519HkdfSha256Aes128Gcm()
      throws GeneralSecurityException {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    HpkePublicKey recipientPublicKey = getPublicKey(parameters);
    HpkePrivateKey recipientPrivateKey = getPrivateKey(recipientPublicKey);
    HybridEncrypt hpkeEncrypt = HpkeEncrypt.create(recipientPublicKey);
    HybridDecrypt hpkeDecrypt = HpkeDecrypt.create(recipientPrivateKey);

    byte[] input = Random.randBytes(200);
    byte[] contextInfo = Random.randBytes(100);
    byte[] ciphertext = hpkeEncrypt.encrypt(input, contextInfo);
    byte[] plaintext = hpkeDecrypt.decrypt(ciphertext, contextInfo);

    expect.that(plaintext).isEqualTo(input);
  }

  @Test
  public void encryptDecrypt_succeedsWithX25519HkdfSha256Aes256Gcm()
      throws GeneralSecurityException {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();
    HpkePublicKey recipientPublicKey = getPublicKey(parameters);
    HpkePrivateKey recipientPrivateKey = getPrivateKey(recipientPublicKey);
    HybridEncrypt hpkeEncrypt = HpkeEncrypt.create(recipientPublicKey);
    HybridDecrypt hpkeDecrypt = HpkeDecrypt.create(recipientPrivateKey);

    byte[] input = Random.randBytes(200);
    byte[] contextInfo = Random.randBytes(100);
    byte[] ciphertext = hpkeEncrypt.encrypt(input, contextInfo);
    byte[] plaintext = hpkeDecrypt.decrypt(ciphertext, contextInfo);

    expect.that(plaintext).isEqualTo(input);
  }

  @Test
  public void encrypt_failsWithNullPlaintext() throws GeneralSecurityException {
    HpkePublicKey recipientPublicKey = getPublicKey(getDefaultValidParams());
    HybridEncrypt hpkeEncrypt = HpkeEncrypt.create(recipientPublicKey);

    byte[] contextInfo = Random.randBytes(100);
    byte[] nullPlaintext = null;

    assertThrows(
        NullPointerException.class, () -> hpkeEncrypt.encrypt(nullPlaintext, contextInfo));
  }

  @Test
  public void decrypt_failsWithModifiedCiphertext() throws GeneralSecurityException {
    HpkePublicKey recipientPublicKey = getPublicKey(getDefaultValidParams());
    HpkePrivateKey recipientPrivateKey = getPrivateKey(recipientPublicKey);
    HybridEncrypt hpkeEncrypt = HpkeEncrypt.create(recipientPublicKey);
    HybridDecrypt hpkeDecrypt = HpkeDecrypt.create(recipientPrivateKey);

    byte[] input = Random.randBytes(200);
    byte[] contextInfo = Random.randBytes(100);
    byte[] ciphertext = hpkeEncrypt.encrypt(input, contextInfo);
    byte[] extendedCiphertext =
        com.google.crypto.tink.subtle.Bytes.concat(
            ciphertext, "modified ciphertext".getBytes(UTF_8));
    byte[] shortCiphertext = Arrays.copyOf(ciphertext, 10);
    byte[] emptyCiphertext = new byte[0];

    expect.that(hpkeDecrypt.decrypt(ciphertext, contextInfo)).isEqualTo(input);
    assertThrows(
        GeneralSecurityException.class, () -> hpkeDecrypt.decrypt(extendedCiphertext, contextInfo));
    assertThrows(
        GeneralSecurityException.class, () -> hpkeDecrypt.decrypt(shortCiphertext, contextInfo));
    assertThrows(
        GeneralSecurityException.class, () -> hpkeDecrypt.decrypt(emptyCiphertext, contextInfo));
  }

  @Test
  public void decrypt_failsWithNullCiphertext() throws GeneralSecurityException {
    HpkePublicKey recipientPublicKey = getPublicKey(getDefaultValidParams());
    HpkePrivateKey recipientPrivateKey = getPrivateKey(recipientPublicKey);
    HybridDecrypt hpkeDecrypt = HpkeDecrypt.create(recipientPrivateKey);

    byte[] contextInfo = Random.randBytes(100);
    byte[] nullCiphertext = null;

    assertThrows(
        NullPointerException.class, () -> hpkeDecrypt.decrypt(nullCiphertext, contextInfo));
  }

  @Test
  public void decrypt_failsWithModifiedContextInfo() throws GeneralSecurityException {
    HpkePublicKey recipientPublicKey = getPublicKey(getDefaultValidParams());
    HpkePrivateKey recipientPrivateKey = getPrivateKey(recipientPublicKey);
    HybridEncrypt hpkeEncrypt = HpkeEncrypt.create(recipientPublicKey);
    HybridDecrypt hpkeDecrypt = HpkeDecrypt.create(recipientPrivateKey);

    byte[] input = Random.randBytes(200);
    byte[] contextInfo = Random.randBytes(100);
    byte[] ciphertext = hpkeEncrypt.encrypt(input, contextInfo);
    byte[] extendedContextInfo =
        com.google.crypto.tink.subtle.Bytes.concat(contextInfo, "modified context".getBytes(UTF_8));
    byte[] shortContextInfo = Arrays.copyOf(contextInfo, 10);
    byte[] emptyContextInfo = new byte[0];
    byte[] nullContextInfo = null;

    expect.that(hpkeDecrypt.decrypt(ciphertext, contextInfo)).isEqualTo(input);
    assertThrows(
        GeneralSecurityException.class, () -> hpkeDecrypt.decrypt(ciphertext, extendedContextInfo));
    assertThrows(
        GeneralSecurityException.class, () -> hpkeDecrypt.decrypt(ciphertext, shortContextInfo));
    assertThrows(
        GeneralSecurityException.class, () -> hpkeDecrypt.decrypt(ciphertext, emptyContextInfo));
    assertThrows(
        GeneralSecurityException.class, () -> hpkeDecrypt.decrypt(ciphertext, nullContextInfo));
  }

  @Test
  public void encryptDecrypt_succeedsWithNullContextInfo() throws GeneralSecurityException {
    HpkePublicKey recipientPublicKey = getPublicKey(getDefaultValidParams());
    HpkePrivateKey recipientPrivateKey = getPrivateKey(recipientPublicKey);
    HybridEncrypt hpkeEncrypt = HpkeEncrypt.create(recipientPublicKey);
    HybridDecrypt hpkeDecrypt = HpkeDecrypt.create(recipientPrivateKey);

    byte[] input = Random.randBytes(200);
    byte[] emptyContextInfo = new byte[0];
    byte[] nullContextInfo = null;
    byte[] ciphertextWithEmptyContext = hpkeEncrypt.encrypt(input, emptyContextInfo);
    byte[] ciphertextWithNullContext = hpkeEncrypt.encrypt(input, nullContextInfo);

    expect.that(hpkeDecrypt.decrypt(ciphertextWithEmptyContext, emptyContextInfo)).isEqualTo(input);
    expect.that(hpkeDecrypt.decrypt(ciphertextWithEmptyContext, nullContextInfo)).isEqualTo(input);
    expect.that(hpkeDecrypt.decrypt(ciphertextWithNullContext, emptyContextInfo)).isEqualTo(input);
    expect.that(hpkeDecrypt.decrypt(ciphertextWithNullContext, nullContextInfo)).isEqualTo(input);
  }

  @Test
  public void flipMsbOfEncapsulatedKeyInCiphertext_fails() throws GeneralSecurityException {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();
    HpkePublicKey recipientPublicKey = getPublicKey(parameters);
    HpkePrivateKey recipientPrivateKey = getPrivateKey(recipientPublicKey);
    HybridEncrypt hpkeEncrypt = HpkeEncrypt.create(recipientPublicKey);
    HybridDecrypt hpkeDecrypt = HpkeDecrypt.create(recipientPrivateKey);

    byte[] input = Random.randBytes(100);
    byte[] contextInfo = Random.randBytes(100);
    byte[] ciphertext = hpkeEncrypt.encrypt(input, contextInfo);

    expect.that(hpkeDecrypt.decrypt(ciphertext, contextInfo)).isEqualTo(input);

    // The first 32 bytes are the encapsulatedKey. Flip its MSB.
    ciphertext[31] = (byte) (ciphertext[31] ^ 128);
    assertThrows(
        GeneralSecurityException.class, () -> hpkeDecrypt.decrypt(ciphertext, contextInfo));
  }

  @DataPoints("testVectors")
  public static final HybridTestVector[] HYBRID_TEST_VECTORS = HpkeTestUtil.createHpkeTestVectors();

  @Theory
  public void decryptCiphertext_works(@FromDataPoints("testVectors") HybridTestVector v)
      throws Exception {
    HybridDecrypt hybridDecrypt =
        HpkeDecrypt.create((com.google.crypto.tink.hybrid.HpkePrivateKey) v.getPrivateKey());
    byte[] plaintext = hybridDecrypt.decrypt(v.getCiphertext(), v.getContextInfo());
    assertThat(Hex.encode(plaintext)).isEqualTo(Hex.encode(v.getPlaintext()));
  }

  @Theory
  public void decryptWrongContextInfo_throws(@FromDataPoints("testVectors") HybridTestVector v)
      throws Exception {
    HybridDecrypt hybridDecrypt =
        HpkeDecrypt.create((com.google.crypto.tink.hybrid.HpkePrivateKey) v.getPrivateKey());
    byte[] contextInfo = v.getContextInfo();
    if (contextInfo.length > 0) {
      contextInfo[0] ^= 1;
    } else {
      contextInfo = new byte[] {1};
    }
    // local variables referenced from a lambda expression must be final or effectively final
    final byte[] contextInfoCopy = Arrays.copyOf(contextInfo, contextInfo.length);
    assertThrows(
        GeneralSecurityException.class,
        () -> hybridDecrypt.decrypt(v.getCiphertext(), contextInfoCopy));
  }

  @Theory
  public void encryptThenDecryptMessage_works(@FromDataPoints("testVectors") HybridTestVector v)
      throws Exception {
    HybridDecrypt hybridDecrypt =
        HpkeDecrypt.create((com.google.crypto.tink.hybrid.HpkePrivateKey) v.getPrivateKey());
    HybridEncrypt hybridEncrypt =
        HpkeEncrypt.create(
            (com.google.crypto.tink.hybrid.HpkePublicKey) v.getPrivateKey().getPublicKey());
    byte[] ciphertext = hybridEncrypt.encrypt(v.getPlaintext(), v.getContextInfo());
    byte[] plaintext = hybridDecrypt.decrypt(ciphertext, v.getContextInfo());
    assertThat(Hex.encode(plaintext)).isEqualTo(Hex.encode(v.getPlaintext()));
  }
}
