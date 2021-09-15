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

import static org.junit.Assert.assertThrows;

import com.google.common.truth.Expect;
import com.google.crypto.tink.testing.HpkeTestUtil;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link X25519HkdfHpkeKemTest}. */
@RunWith(JUnit4.class)
public final class X25519HkdfHpkeKemTest {
  private static final String MAC_ALGORITHM = "HmacSha256";

  @Rule public final Expect expect = Expect.create();

  private void encapsulate(HpkeTestUtil.TestVector testVector) throws GeneralSecurityException {
    X25519HkdfHpkeKem kem = new X25519HkdfHpkeKem(MAC_ALGORITHM);
    HpkeKemEncapOutput result =
        kem.encapsulate(testVector.recipientPublicKey, testVector.senderPrivateKey);
    expect.that(result.getSharedSecret()).isEqualTo(testVector.sharedSecret);
    expect.that(result.getEncapsulatedKey()).isEqualTo(testVector.encapsulatedKey);
  }

  private void decapsulate(HpkeTestUtil.TestVector testVector) throws GeneralSecurityException {
    X25519HkdfHpkeKem kem = new X25519HkdfHpkeKem(MAC_ALGORITHM);
    byte[] result = kem.decapsulate(testVector.encapsulatedKey, testVector.recipientPrivateKey);
    expect.that(result).isEqualTo(testVector.sharedSecret);
  }

  @Test
  public void encapsulate_succeedsWithX25519HkdfSha256Aes128Gcm() throws GeneralSecurityException {
    encapsulate(HpkeTestUtil.X25519_HKDF_SHA256_AES_128_GCM_TEST);
  }

  @Test
  public void encapsulate_succeedsWithX25519HkdfSha256ChaChaPoly1305()
      throws GeneralSecurityException {
    encapsulate(HpkeTestUtil.X25519_HKDF_SHA256_CHACHAPOLY1305_TEST);
  }

  @Test
  public void encapsulate_succeedsWithX25519HkdfSha256ExportOnlyAead()
      throws GeneralSecurityException {
    encapsulate(HpkeTestUtil.X25519_HKDF_SHA256_EXPORT_ONLY_AEAD_TEST);
  }

  @Test
  public void encapsulate_failsWithInvalidMacAlgorithm() {
    X25519HkdfHpkeKem kem = new X25519HkdfHpkeKem("BadMac");
    byte[] validRecipientPublicKey =
        HpkeTestUtil.X25519_HKDF_SHA256_AES_128_GCM_TEST.recipientPublicKey;
    assertThrows(NoSuchAlgorithmException.class, () -> kem.encapsulate(validRecipientPublicKey));
  }

  @Test
  public void encapsulate_failsWithInvalidRecipientPublicKey() {
    X25519HkdfHpkeKem kem = new X25519HkdfHpkeKem(MAC_ALGORITHM);
    byte[] invalidRecipientPublicKey =
        Arrays.copyOf(
            HpkeTestUtil.X25519_HKDF_SHA256_AES_128_GCM_TEST.recipientPublicKey,
            HpkeTestUtil.X25519_HKDF_SHA256_AES_128_GCM_TEST.recipientPublicKey.length + 2);
    assertThrows(InvalidKeyException.class, () -> kem.encapsulate(invalidRecipientPublicKey));
  }

  @Test
  public void decapsulate_succeedsWithX25519HkdfSha256Aes128Gcm() throws GeneralSecurityException {
    decapsulate(HpkeTestUtil.X25519_HKDF_SHA256_AES_128_GCM_TEST);
  }

  @Test
  public void decapsulate_succeedsWithX25519HkdfSha256ChaChaPoly1305()
      throws GeneralSecurityException {
    decapsulate(HpkeTestUtil.X25519_HKDF_SHA256_CHACHAPOLY1305_TEST);
  }

  @Test
  public void decapsulate_succeedsWithX25519HkdfSha256ExportOnlyAead()
      throws GeneralSecurityException {
    decapsulate(HpkeTestUtil.X25519_HKDF_SHA256_EXPORT_ONLY_AEAD_TEST);
  }

  @Test
  public void decapsulate_failsWithInvalidMacAlgorithm() {
    X25519HkdfHpkeKem kem = new X25519HkdfHpkeKem("BadMac");
    byte[] validEncapsulatedKey = HpkeTestUtil.X25519_HKDF_SHA256_AES_128_GCM_TEST.encapsulatedKey;
    byte[] validRecipientPrivateKey =
        HpkeTestUtil.X25519_HKDF_SHA256_AES_128_GCM_TEST.recipientPrivateKey;
    assertThrows(
        NoSuchAlgorithmException.class,
        () -> kem.decapsulate(validEncapsulatedKey, validRecipientPrivateKey));
  }

  @Test
  public void decapsulate_failsWithInvalidEncapsulatedPublicKey() {
    X25519HkdfHpkeKem kem = new X25519HkdfHpkeKem(MAC_ALGORITHM);
    byte[] invalidEncapsulatedKey =
        Arrays.copyOf(
            HpkeTestUtil.X25519_HKDF_SHA256_AES_128_GCM_TEST.encapsulatedKey,
            HpkeTestUtil.X25519_HKDF_SHA256_AES_128_GCM_TEST.encapsulatedKey.length + 2);
    byte[] validRecipientPrivateKey =
        HpkeTestUtil.X25519_HKDF_SHA256_AES_128_GCM_TEST.recipientPrivateKey;
    assertThrows(
        InvalidKeyException.class,
        () -> kem.decapsulate(invalidEncapsulatedKey, validRecipientPrivateKey));
  }

  @Test
  public void decapsulate_failsWithInvalidRecipientPrivateKey() {
    X25519HkdfHpkeKem kem = new X25519HkdfHpkeKem(MAC_ALGORITHM);
    byte[] validEncapsulatedKey = HpkeTestUtil.X25519_HKDF_SHA256_AES_128_GCM_TEST.encapsulatedKey;
    byte[] invalidRecipientPrivateKey =
        Arrays.copyOf(
            HpkeTestUtil.X25519_HKDF_SHA256_AES_128_GCM_TEST.recipientPrivateKey,
            HpkeTestUtil.X25519_HKDF_SHA256_AES_128_GCM_TEST.recipientPrivateKey.length + 2);
    assertThrows(
        InvalidKeyException.class,
        () -> kem.decapsulate(validEncapsulatedKey, invalidRecipientPrivateKey));
  }
}
