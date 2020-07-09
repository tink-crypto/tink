// Copyright 2017 Google Inc.
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

package com.google.crypto.tink.hybrid;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridEncrypt;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.CurveType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.TestUtil.BytesMutation;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link EciesAeadHkdfHybridDecrypt}. */
@RunWith(JUnit4.class)
public class EciesAeadHkdfHybridDecryptTest {
  @Before
  public void setUp() throws GeneralSecurityException {
    Config.register(HybridConfig.TINK_1_0_0);
  }

  private static void testEncryptDecrypt(CurveType curveType, KeyTemplate keyTemplate)
      throws Exception {
    KeyPair recipientKey = EllipticCurves.generateKeyPair(curveType);
    ECPublicKey recipientPublicKey = (ECPublicKey) recipientKey.getPublic();
    ECPrivateKey recipientPrivateKey = (ECPrivateKey) recipientKey.getPrivate();
    byte[] salt = Random.randBytes(8);
    String hmacAlgo = HybridUtil.toHmacAlgo(HashType.SHA256);
    byte[] plaintext = Random.randBytes(4);
    byte[] context = Random.randBytes(4);
    HybridEncrypt hybridEncrypt =
        new EciesAeadHkdfHybridEncrypt(
            recipientPublicKey,
            salt,
            hmacAlgo,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            new RegistryEciesAeadHkdfDemHelper(keyTemplate));
    HybridDecrypt hybridDecrypt =
        new EciesAeadHkdfHybridDecrypt(
            recipientPrivateKey,
            salt,
            hmacAlgo,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            new RegistryEciesAeadHkdfDemHelper(keyTemplate));
    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, context);
    byte[] decrypted = hybridDecrypt.decrypt(ciphertext, context);
    assertArrayEquals(plaintext, decrypted);
  }

  @Test
  public void testEncryptDecryptP256CtrHmac() throws Exception {
    testEncryptDecrypt(CurveType.NIST_P256, AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
  }

  @Test
  public void testEncryptDecryptP384CtrHmac() throws Exception {
    testEncryptDecrypt(CurveType.NIST_P384, AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
  }

  @Test
  public void testEncryptDecryptP521CtrHmac() throws Exception {
    testEncryptDecrypt(CurveType.NIST_P521, AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
  }

  @Test
  public void testEncryptDecryptP256Gcm() throws Exception {
    testEncryptDecrypt(CurveType.NIST_P256, AeadKeyTemplates.AES128_GCM);
  }

  @Test
  public void testEncryptDecryptP384Gcm() throws Exception {
    testEncryptDecrypt(CurveType.NIST_P384, AeadKeyTemplates.AES128_GCM);
  }

  @Test
  public void testEncryptDecryptP512Gcm() throws Exception {
    testEncryptDecrypt(CurveType.NIST_P521, AeadKeyTemplates.AES128_GCM);
  }

  private static void testEncryptDecrypt_mutatedCiphertext_throws(
      CurveType curveType, KeyTemplate keyTemplate) throws Exception {
    KeyPair recipientKey = EllipticCurves.generateKeyPair(curveType);
    ECPublicKey recipientPublicKey = (ECPublicKey) recipientKey.getPublic();
    ECPrivateKey recipientPrivateKey = (ECPrivateKey) recipientKey.getPrivate();
    byte[] salt = Random.randBytes(8);
    String hmacAlgo = HybridUtil.toHmacAlgo(HashType.SHA256);
    byte[] plaintext = Random.randBytes(4);
    byte[] context = Random.randBytes(4);
    HybridEncrypt hybridEncrypt =
        new EciesAeadHkdfHybridEncrypt(
            recipientPublicKey,
            salt,
            hmacAlgo,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            new RegistryEciesAeadHkdfDemHelper(keyTemplate));
    HybridDecrypt hybridDecrypt =
        new EciesAeadHkdfHybridDecrypt(
            recipientPrivateKey,
            salt,
            hmacAlgo,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            new RegistryEciesAeadHkdfDemHelper(keyTemplate));
    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, context);
    for (BytesMutation mutation : TestUtil.generateMutations(ciphertext)) {
      assertThrows(
          GeneralSecurityException.class, () -> hybridDecrypt.decrypt(mutation.value, context));
      // The test takes too long in TSan, so we stop after the first case.
      if (TestUtil.isTsan()) {
        return;
      }
    }
  }

  @Test
  public void testEncryptDecryptP256CtrHmac_mutatedCiphertext_throws() throws Exception {
    testEncryptDecrypt_mutatedCiphertext_throws(
        CurveType.NIST_P256, AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
  }

  @Test
  public void testEncryptDecryptP384CtrHmac_mutatedCiphertext_throws() throws Exception {
    testEncryptDecrypt_mutatedCiphertext_throws(
        CurveType.NIST_P384, AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
  }

  @Test
  public void testEncryptDecryptP521CtrHmac_mutatedCiphertext_throws() throws Exception {
    testEncryptDecrypt_mutatedCiphertext_throws(
        CurveType.NIST_P521, AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
  }

  @Test
  public void testEncryptDecryptP256Gcm_mutatedCiphertext_throws() throws Exception {
    testEncryptDecrypt_mutatedCiphertext_throws(CurveType.NIST_P256, AeadKeyTemplates.AES128_GCM);
  }

  @Test
  public void testEncryptDecryptP384Gcm_mutatedCiphertext_throws() throws Exception {
    testEncryptDecrypt_mutatedCiphertext_throws(CurveType.NIST_P384, AeadKeyTemplates.AES128_GCM);
  }

  @Test
  public void testEncryptDecryptP512Gcm_mutatedCiphertext_throws() throws Exception {
    testEncryptDecrypt_mutatedCiphertext_throws(CurveType.NIST_P521, AeadKeyTemplates.AES128_GCM);
  }

  private static void testEncryptDecrypt_mutatedContext_throws(
      CurveType curveType, KeyTemplate keyTemplate) throws Exception {
    KeyPair recipientKey = EllipticCurves.generateKeyPair(curveType);
    ECPublicKey recipientPublicKey = (ECPublicKey) recipientKey.getPublic();
    ECPrivateKey recipientPrivateKey = (ECPrivateKey) recipientKey.getPrivate();
    byte[] salt = Random.randBytes(8);
    String hmacAlgo = HybridUtil.toHmacAlgo(HashType.SHA256);
    byte[] plaintext = Random.randBytes(4);
    byte[] context = Random.randBytes(4);
    HybridEncrypt hybridEncrypt =
        new EciesAeadHkdfHybridEncrypt(
            recipientPublicKey,
            salt,
            hmacAlgo,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            new RegistryEciesAeadHkdfDemHelper(keyTemplate));
    HybridDecrypt hybridDecrypt =
        new EciesAeadHkdfHybridDecrypt(
            recipientPrivateKey,
            salt,
            hmacAlgo,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            new RegistryEciesAeadHkdfDemHelper(keyTemplate));
    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, context);
    for (BytesMutation mutation : TestUtil.generateMutations(context)) {
      // The test takes too long in TSan, so we stop after the first case.
      assertThrows(
          GeneralSecurityException.class, () -> hybridDecrypt.decrypt(ciphertext, mutation.value));
      if (TestUtil.isTsan()) {
        return;
      }
    }
  }

  @Test
  public void testEncryptDecryptP256CtrHmac_mutatedContext_throws() throws Exception {
    testEncryptDecrypt_mutatedContext_throws(
        CurveType.NIST_P256, AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
  }

  @Test
  public void testEncryptDecryptP384CtrHmac_mutatedContext_throws() throws Exception {
    testEncryptDecrypt_mutatedContext_throws(
        CurveType.NIST_P384, AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
  }

  @Test
  public void testEncryptDecryptP521CtrHmac_mutatedContext_throws() throws Exception {
    testEncryptDecrypt_mutatedContext_throws(CurveType.NIST_P521, AeadKeyTemplates.AES128_GCM);
  }

  @Test
  public void testEncryptDecryptP256Gcm_mutatedContext_throws() throws Exception {
    testEncryptDecrypt_mutatedContext_throws(CurveType.NIST_P256, AeadKeyTemplates.AES128_GCM);
  }

  @Test
  public void testEncryptDecryptP384Gcm_mutatedContext_throws() throws Exception {
    testEncryptDecrypt_mutatedContext_throws(CurveType.NIST_P384, AeadKeyTemplates.AES128_GCM);
  }

  @Test
  public void testEncryptDecryptP512Gcm_mutatedContext_throws() throws Exception {
    testEncryptDecrypt_mutatedContext_throws(CurveType.NIST_P521, AeadKeyTemplates.AES128_GCM);
  }

  private static void testEncryptDecrypt_mutatedSalt_throws(
      CurveType curveType, KeyTemplate keyTemplate) throws Exception {
    KeyPair recipientKey = EllipticCurves.generateKeyPair(curveType);
    ECPublicKey recipientPublicKey = (ECPublicKey) recipientKey.getPublic();
    ECPrivateKey recipientPrivateKey = (ECPrivateKey) recipientKey.getPrivate();
    byte[] salt = Random.randBytes(8);
    String hmacAlgo = HybridUtil.toHmacAlgo(HashType.SHA256);
    byte[] plaintext = Random.randBytes(4);
    byte[] context = Random.randBytes(4);
    HybridEncrypt hybridEncrypt =
        new EciesAeadHkdfHybridEncrypt(
            recipientPublicKey,
            salt,
            hmacAlgo,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            new RegistryEciesAeadHkdfDemHelper(keyTemplate));
    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, context);

    for (int bytes = 0; bytes < salt.length; bytes++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modifiedSalt = Arrays.copyOf(salt, salt.length);
        modifiedSalt[bytes] ^= (byte) (1 << bit);
        HybridDecrypt hybridDecrypt =
            new EciesAeadHkdfHybridDecrypt(
                recipientPrivateKey,
                modifiedSalt,
                hmacAlgo,
                EllipticCurves.PointFormatType.UNCOMPRESSED,
                new RegistryEciesAeadHkdfDemHelper(keyTemplate));
        assertThrows(
            GeneralSecurityException.class, () -> hybridDecrypt.decrypt(ciphertext, modifiedSalt));
        // The test takes too long in TSan, so we stop after the first case.
        if (TestUtil.isTsan()) {
          return;
        }
      }
    }
  }

  @Test
  public void testEncryptDecryptP256CtrHmac_mutatedSalt_throws() throws Exception {
    testEncryptDecrypt_mutatedSalt_throws(
        CurveType.NIST_P256, AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
  }

  @Test
  public void testEncryptDecryptP384CtrHmac_mutatedSalt_throws() throws Exception {
    testEncryptDecrypt_mutatedSalt_throws(
        CurveType.NIST_P384, AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
  }

  @Test
  public void testEncryptDecryptP521CtrHmac_mutatedSalt_throws() throws Exception {
    testEncryptDecrypt_mutatedSalt_throws(
        CurveType.NIST_P521, AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
  }

  @Test
  public void testEncryptDecryptP256Gcm_mutatedSalt_throws() throws Exception {
    testEncryptDecrypt_mutatedSalt_throws(CurveType.NIST_P256, AeadKeyTemplates.AES128_GCM);
  }

  @Test
  public void testEncryptDecryptP384Gcm_mutatedSalt_throws() throws Exception {
    testEncryptDecrypt_mutatedSalt_throws(CurveType.NIST_P384, AeadKeyTemplates.AES128_GCM);
  }

  @Test
  public void testEncryptDecryptP512Gcm_mutatedSalt_throws() throws Exception {
    testEncryptDecrypt_mutatedSalt_throws(CurveType.NIST_P521, AeadKeyTemplates.AES128_GCM);
  }
}
