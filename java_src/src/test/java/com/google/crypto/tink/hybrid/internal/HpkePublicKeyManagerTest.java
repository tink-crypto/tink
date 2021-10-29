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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.proto.HpkeAead;
import com.google.crypto.tink.proto.HpkeKdf;
import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.HpkePublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.X25519;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link HpkePublicKeyManager}. */
@RunWith(JUnit4.class)
public final class HpkePublicKeyManagerTest {
  private static byte[] publicKeyBytes;

  private HpkePublicKeyManager keyManager;

  @BeforeClass
  public static void generateKeyMaterial() throws GeneralSecurityException {
    publicKeyBytes = X25519.publicFromPrivate(X25519.generatePrivateKey());
  }

  @Before
  public void setUp() {
    keyManager = new HpkePublicKeyManager();
  }

  private HpkeParams createValidHpkeParams() {
    return HpkeParams.newBuilder()
        .setKem(HpkeKem.DHKEM_X25519_HKDF_SHA256)
        .setKdf(HpkeKdf.HKDF_SHA256)
        .setAead(HpkeAead.AES_256_GCM)
        .build();
  }

  private HpkePublicKey createHpkePublicKey(HpkeParams params) {
    return HpkePublicKey.newBuilder()
        .setVersion(0)
        .setPublicKey(ByteString.copyFrom(publicKeyBytes))
        .setParams(params)
        .build();
  }

  private HpkePublicKey createValidHpkePublicKey() {
    return createHpkePublicKey(createValidHpkeParams());
  }

  @Test
  public void basics() throws Exception {
    assertThat(keyManager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.HpkePublicKey");
    assertThat(keyManager.getVersion()).isEqualTo(0);
    assertThat(keyManager.keyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
  }

  @Test
  public void validateKey_succeedsWithValidKey() throws Exception {
    keyManager.validateKey(createValidHpkePublicKey());
  }

  @Test
  public void validateKey_failsWithEmptyKey() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> keyManager.validateKey(HpkePublicKey.getDefaultInstance()));
  }

  @Test
  public void validateKey_failsWithWrongVersion() throws Exception {
    HpkePublicKey wrongVersionKey =
        HpkePublicKey.newBuilder(createValidHpkePublicKey()).setVersion(1).build();
    assertThrows(GeneralSecurityException.class, () -> keyManager.validateKey(wrongVersionKey));
  }

  @Test
  public void validateKey_failsWithMissingParams() throws Exception {
    HpkePublicKey missingParamsKey =
        HpkePublicKey.newBuilder(createValidHpkePublicKey()).clearParams().build();
    assertThrows(GeneralSecurityException.class, () -> keyManager.validateKey(missingParamsKey));
  }

  @Test
  public void validateKey_failsWithInvalidKem() throws Exception {
    HpkeParams invalidKemParams =
        HpkeParams.newBuilder()
            .setKem(HpkeKem.KEM_UNKNOWN)
            .setKdf(HpkeKdf.HKDF_SHA256)
            .setAead(HpkeAead.AES_256_GCM)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> keyManager.validateKey(createHpkePublicKey(invalidKemParams)));
  }

  @Test
  public void validateKey_failsWithInvalidKdf() throws Exception {
    HpkeParams invalidKdfParams =
        HpkeParams.newBuilder()
            .setKem(HpkeKem.DHKEM_X25519_HKDF_SHA256)
            .setKdf(HpkeKdf.KDF_UNKNOWN)
            .setAead(HpkeAead.AES_256_GCM)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> keyManager.validateKey(createHpkePublicKey(invalidKdfParams)));
  }

  @Test
  public void validateKey_failsWithInvalidAead() throws Exception {
    HpkeParams invalidAeadParams =
        HpkeParams.newBuilder()
            .setKem(HpkeKem.DHKEM_X25519_HKDF_SHA256)
            .setKdf(HpkeKdf.HKDF_SHA256)
            .setAead(HpkeAead.AEAD_UNKNOWN)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> keyManager.validateKey(createHpkePublicKey(invalidAeadParams)));
  }

  @Test
  public void createPrimitive() throws Exception {
    HpkePublicKey publicKey = createValidHpkePublicKey();
    HybridEncrypt hybridEncrypt = keyManager.getPrimitive(publicKey, HybridEncrypt.class);

    // TODO(b/187527392): Confirm that decryption succeeds after implementing HpkePrivateKeyManager.
    byte[] input = Random.randBytes(200);
    byte[] contextInfo = Random.randBytes(100);
    hybridEncrypt.encrypt(input, contextInfo);
  }
}
