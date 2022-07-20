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
import static org.junit.Assert.assertThrows;

import com.google.common.truth.Expect;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.HpkePrivateKey;
import com.google.crypto.tink.proto.HpkePublicKey;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.X25519;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link HpkeEncrypt} and {@link HpkeDecrypt}. */
@RunWith(JUnit4.class)
public final class HpkeEncryptDecryptTest {
  private static byte[] privateKeyBytes;
  private static byte[] publicKeyBytes;

  @Rule public final Expect expect = Expect.create();

  @BeforeClass
  public static void generateKeyMaterial() throws GeneralSecurityException {
    privateKeyBytes = X25519.generatePrivateKey();
    publicKeyBytes = X25519.publicFromPrivate(privateKeyBytes);
  }

  private HpkeParams getParams(
      com.google.crypto.tink.proto.HpkeKem kem,
      com.google.crypto.tink.proto.HpkeKdf kdf,
      com.google.crypto.tink.proto.HpkeAead aead) {
    return HpkeParams.newBuilder().setKem(kem).setKdf(kdf).setAead(aead).build();
  }

  private HpkeParams getDefaultValidParams() {
    return getParams(
        com.google.crypto.tink.proto.HpkeKem.DHKEM_X25519_HKDF_SHA256,
        com.google.crypto.tink.proto.HpkeKdf.HKDF_SHA256,
        com.google.crypto.tink.proto.HpkeAead.AES_256_GCM);
  }

  private HpkePublicKey getPublicKey(HpkeParams params) {
    return HpkePublicKey.newBuilder()
        .setPublicKey(ByteString.copyFrom(publicKeyBytes))
        .setParams(params)
        .build();
  }

  private HpkePrivateKey getPrivateKey(HpkePublicKey publicKey) {
    return HpkePrivateKey.newBuilder()
        .setPrivateKey(ByteString.copyFrom(privateKeyBytes))
        .setPublicKey(publicKey)
        .build();
  }

  @Test
  public void create_failsWithUnknownKem() {
    HpkeParams params =
        HpkeParams.newBuilder(getDefaultValidParams())
            .setKem(com.google.crypto.tink.proto.HpkeKem.KEM_UNKNOWN)
            .build();
    HpkePublicKey recipientPublicKey = getPublicKey(params);
    HpkePrivateKey recipientPrivateKey = getPrivateKey(recipientPublicKey);

    assertThrows(
        IllegalArgumentException.class, () -> HpkeEncrypt.createHpkeEncrypt(recipientPublicKey));
    assertThrows(
        IllegalArgumentException.class, () -> HpkeDecrypt.createHpkeDecrypt(recipientPrivateKey));
  }

  @Test
  public void create_failsWithUnknownKdf() {
    HpkeParams params =
        HpkeParams.newBuilder(getDefaultValidParams())
            .setKdf(com.google.crypto.tink.proto.HpkeKdf.KDF_UNKNOWN)
            .build();
    HpkePublicKey recipientPublicKey = getPublicKey(params);
    HpkePrivateKey recipientPrivateKey = getPrivateKey(recipientPublicKey);

    assertThrows(
        IllegalArgumentException.class, () -> HpkeEncrypt.createHpkeEncrypt(recipientPublicKey));
    assertThrows(
        IllegalArgumentException.class, () -> HpkeDecrypt.createHpkeDecrypt(recipientPrivateKey));
  }

  @Test
  public void create_failsWithUnknownAead() {
    HpkeParams params =
        HpkeParams.newBuilder(getDefaultValidParams())
            .setAead(com.google.crypto.tink.proto.HpkeAead.AEAD_UNKNOWN)
            .build();
    HpkePublicKey recipientPublicKey = getPublicKey(params);
    HpkePrivateKey recipientPrivateKey = getPrivateKey(recipientPublicKey);

    assertThrows(
        IllegalArgumentException.class, () -> HpkeEncrypt.createHpkeEncrypt(recipientPublicKey));
    assertThrows(
        IllegalArgumentException.class, () -> HpkeDecrypt.createHpkeDecrypt(recipientPrivateKey));
  }

  @Test
  public void create_failsWithMissingPublicKey() {
    HpkePrivateKey recipientPrivateKey =
        HpkePrivateKey.newBuilder().setPrivateKey(ByteString.copyFrom(privateKeyBytes)).build();

    assertThrows(
        IllegalArgumentException.class, () -> HpkeDecrypt.createHpkeDecrypt(recipientPrivateKey));
  }

  @Test
  public void create_failsWithMissingHpkeParams() {
    HpkePublicKey missingParamsPublicKey =
        HpkePublicKey.newBuilder().setPublicKey(ByteString.copyFrom(publicKeyBytes)).build();
    HpkePrivateKey recipientPrivateKey =
        HpkePrivateKey.newBuilder()
            .setPrivateKey(ByteString.copyFrom(privateKeyBytes))
            .setPublicKey(missingParamsPublicKey)
            .build();

    assertThrows(
        IllegalArgumentException.class,
        () -> HpkeEncrypt.createHpkeEncrypt(missingParamsPublicKey));
    assertThrows(
        IllegalArgumentException.class, () -> HpkeDecrypt.createHpkeDecrypt(recipientPrivateKey));
  }

  @Test
  public void create_failsWithZeroLengthPublicKey() {
    HpkePublicKey recipientPublicKey =
        HpkePublicKey.newBuilder()
            .setParams(getDefaultValidParams())
            .setPublicKey(ByteString.EMPTY)
            .build();

    assertThrows(
        IllegalArgumentException.class, () -> HpkeEncrypt.createHpkeEncrypt(recipientPublicKey));
  }

  @Test
  public void create_failsWithZeroLengthPrivateKey() {
    HpkePublicKey recipientPublicKey = getPublicKey(getDefaultValidParams());
    HpkePrivateKey recipientPrivateKey =
        HpkePrivateKey.newBuilder()
            .setPublicKey(recipientPublicKey)
            .setPrivateKey(ByteString.EMPTY)
            .build();

    assertThrows(
        IllegalArgumentException.class, () -> HpkeDecrypt.createHpkeDecrypt(recipientPrivateKey));
  }

  @Test
  public void encryptDecrypt_succeedsWithX25519HkdfSha256Aes128Gcm()
      throws GeneralSecurityException {
    HpkeParams params =
        getParams(
            com.google.crypto.tink.proto.HpkeKem.DHKEM_X25519_HKDF_SHA256,
            com.google.crypto.tink.proto.HpkeKdf.HKDF_SHA256,
            com.google.crypto.tink.proto.HpkeAead.AES_128_GCM);
    HpkePublicKey recipientPublicKey = getPublicKey(params);
    HpkePrivateKey recipientPrivateKey = getPrivateKey(recipientPublicKey);
    HybridEncrypt hpkeEncrypt = HpkeEncrypt.createHpkeEncrypt(recipientPublicKey);
    HybridDecrypt hpkeDecrypt = HpkeDecrypt.createHpkeDecrypt(recipientPrivateKey);

    byte[] input = Random.randBytes(200);
    byte[] contextInfo = Random.randBytes(100);
    byte[] ciphertext = hpkeEncrypt.encrypt(input, contextInfo);
    byte[] plaintext = hpkeDecrypt.decrypt(ciphertext, contextInfo);

    expect.that(plaintext).isEqualTo(input);
  }

  @Test
  public void encryptDecrypt_succeedsWithX25519HkdfSha256Aes256Gcm()
      throws GeneralSecurityException {
    HpkeParams params =
        getParams(
            com.google.crypto.tink.proto.HpkeKem.DHKEM_X25519_HKDF_SHA256,
            com.google.crypto.tink.proto.HpkeKdf.HKDF_SHA256,
            com.google.crypto.tink.proto.HpkeAead.AES_256_GCM);
    HpkePublicKey recipientPublicKey = getPublicKey(params);
    HpkePrivateKey recipientPrivateKey = getPrivateKey(recipientPublicKey);
    HybridEncrypt hpkeEncrypt = HpkeEncrypt.createHpkeEncrypt(recipientPublicKey);
    HybridDecrypt hpkeDecrypt = HpkeDecrypt.createHpkeDecrypt(recipientPrivateKey);

    byte[] input = Random.randBytes(200);
    byte[] contextInfo = Random.randBytes(100);
    byte[] ciphertext = hpkeEncrypt.encrypt(input, contextInfo);
    byte[] plaintext = hpkeDecrypt.decrypt(ciphertext, contextInfo);

    expect.that(plaintext).isEqualTo(input);
  }

  @Test
  public void encrypt_failsWithNullPlaintext() throws GeneralSecurityException {
    HpkePublicKey recipientPublicKey = getPublicKey(getDefaultValidParams());
    HybridEncrypt hpkeEncrypt = HpkeEncrypt.createHpkeEncrypt(recipientPublicKey);

    byte[] contextInfo = Random.randBytes(100);
    byte[] nullPlaintext = null;

    assertThrows(
        NullPointerException.class, () -> hpkeEncrypt.encrypt(nullPlaintext, contextInfo));
  }

  @Test
  public void decrypt_failsWithModifiedCiphertext() throws GeneralSecurityException {
    HpkePublicKey recipientPublicKey = getPublicKey(getDefaultValidParams());
    HpkePrivateKey recipientPrivateKey = getPrivateKey(recipientPublicKey);
    HybridEncrypt hpkeEncrypt = HpkeEncrypt.createHpkeEncrypt(recipientPublicKey);
    HybridDecrypt hpkeDecrypt = HpkeDecrypt.createHpkeDecrypt(recipientPrivateKey);

    byte[] input = Random.randBytes(200);
    byte[] contextInfo = Random.randBytes(100);
    byte[] ciphertext = hpkeEncrypt.encrypt(input, contextInfo);
    byte[] extendedCiphertext = Bytes.concat(ciphertext, "modified ciphertext".getBytes(UTF_8));
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
    HybridDecrypt hpkeDecrypt = HpkeDecrypt.createHpkeDecrypt(recipientPrivateKey);

    byte[] contextInfo = Random.randBytes(100);
    byte[] nullCiphertext = null;

    assertThrows(
        NullPointerException.class, () -> hpkeDecrypt.decrypt(nullCiphertext, contextInfo));
  }

  @Test
  public void decrypt_failsWithModifiedContextInfo() throws GeneralSecurityException {
    HpkePublicKey recipientPublicKey = getPublicKey(getDefaultValidParams());
    HpkePrivateKey recipientPrivateKey = getPrivateKey(recipientPublicKey);
    HybridEncrypt hpkeEncrypt = HpkeEncrypt.createHpkeEncrypt(recipientPublicKey);
    HybridDecrypt hpkeDecrypt = HpkeDecrypt.createHpkeDecrypt(recipientPrivateKey);

    byte[] input = Random.randBytes(200);
    byte[] contextInfo = Random.randBytes(100);
    byte[] ciphertext = hpkeEncrypt.encrypt(input, contextInfo);
    byte[] extendedContextInfo = Bytes.concat(contextInfo, "modified context".getBytes(UTF_8));
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
    HybridEncrypt hpkeEncrypt = HpkeEncrypt.createHpkeEncrypt(recipientPublicKey);
    HybridDecrypt hpkeDecrypt = HpkeDecrypt.createHpkeDecrypt(recipientPrivateKey);

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
    HpkeParams params =
        getParams(
            com.google.crypto.tink.proto.HpkeKem.DHKEM_X25519_HKDF_SHA256,
            com.google.crypto.tink.proto.HpkeKdf.HKDF_SHA256,
            com.google.crypto.tink.proto.HpkeAead.AES_256_GCM);
    HpkePublicKey recipientPublicKey = getPublicKey(params);
    HpkePrivateKey recipientPrivateKey = getPrivateKey(recipientPublicKey);
    HybridEncrypt hpkeEncrypt = HpkeEncrypt.createHpkeEncrypt(recipientPublicKey);
    HybridDecrypt hpkeDecrypt = HpkeDecrypt.createHpkeDecrypt(recipientPrivateKey);

    byte[] input = Random.randBytes(100);
    byte[] contextInfo = Random.randBytes(100);
    byte[] ciphertext = hpkeEncrypt.encrypt(input, contextInfo);

    expect.that(hpkeDecrypt.decrypt(ciphertext, contextInfo)).isEqualTo(input);

    // The first 32 bytes are the encapsulatedKey. Flip its MSB.
    ciphertext[31] = (byte) (ciphertext[31] ^ 128);
    assertThrows(
        GeneralSecurityException.class, () -> hpkeDecrypt.decrypt(ciphertext, contextInfo));
  }
}
