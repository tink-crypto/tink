// Copyright 2017 Google LLC
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

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.internal.EllipticCurvesUtil;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridEncrypt;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for EciesAeadHkdfHybridEncrypt.
 *
 * <p>TODO(b/74250701): Add more tests.
 */
@RunWith(JUnit4.class)
public class EciesAeadHkdfHybridEncryptTest {
  @Before
  public void setUp() throws GeneralSecurityException {
    HybridConfig.register();
  }

  private static final AesCtrHmacAeadParameters AES128_CTR_HMAC_SHA256_RAW =
      exceptionIsBug(
          () ->
              AesCtrHmacAeadParameters.builder()
                  .setAesKeySizeBytes(16)
                  .setHmacKeySizeBytes(32)
                  .setTagSizeBytes(16)
                  .setIvSizeBytes(16)
                  .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                  .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                  .build());
  private static final AesGcmParameters AES128_GCM_RAW =
      exceptionIsBug(
          () ->
              AesGcmParameters.builder()
                  .setIvSizeBytes(12)
                  .setKeySizeBytes(16)
                  .setTagSizeBytes(16)
                  .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                  .build());
  private static final AesSivParameters AES256_SIV_RAW =
      exceptionIsBug(
          () ->
              AesSivParameters.builder()
                  .setKeySizeBytes(64)
                  .setVariant(AesSivParameters.Variant.NO_PREFIX)
                  .build());

  private static final ECParameterSpec toParameterSpec(EciesParameters.CurveType curveType)
      throws GeneralSecurityException {
    if (curveType == EciesParameters.CurveType.NIST_P256) {
      return EllipticCurvesUtil.NIST_P256_PARAMS;
    }
    if (curveType == EciesParameters.CurveType.NIST_P384) {
      return EllipticCurvesUtil.NIST_P384_PARAMS;
    }
    if (curveType == EciesParameters.CurveType.NIST_P521) {
      return EllipticCurvesUtil.NIST_P521_PARAMS;
    }
    throw new GeneralSecurityException("Unsupported curve type: " + curveType);
  }

  private void testBasicMultipleEncrypts(EciesParameters.CurveType curveType, Parameters parameters)
      throws Exception {
    KeyPair recipientKey = EllipticCurves.generateKeyPair(toParameterSpec(curveType));
    ECPublicKey recipientPublicKey = (ECPublicKey) recipientKey.getPublic();
    ECPrivateKey recipientPrivateKey = (ECPrivateKey) recipientKey.getPrivate();
    byte[] salt = "some salt".getBytes("UTF-8");
    byte[] plaintext = Random.randBytes(20);
    byte[] context = "context info".getBytes("UTF-8");
    EciesParameters eciesParameters =
        EciesParameters.builder()
            .setCurveType(curveType)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(parameters)
            .setSalt(Bytes.copyFrom(salt))
            .build();
    EciesPublicKey eciesPublicKey =
        EciesPublicKey.createForNistCurve(
            eciesParameters, recipientPublicKey.getW(), /* idRequirement= */ null);
    EciesPrivateKey eciesPrivateKey =
        EciesPrivateKey.createForNistCurve(
            eciesPublicKey,
            SecretBigInteger.fromBigInteger(
                recipientPrivateKey.getS(), InsecureSecretKeyAccess.get()));

    HybridEncrypt hybridEncrypt = EciesAeadHkdfHybridEncrypt.create(eciesPublicKey);
    HybridDecrypt hybridDecrypt = EciesAeadHkdfHybridDecrypt.create(eciesPrivateKey);

    // Makes sure that the encryption is randomized.
    Set<String> ciphertexts = new TreeSet<String>();
    for (int j = 0; j < 8; j++) {
      byte[] ciphertext = hybridEncrypt.encrypt(plaintext, context);
      if (ciphertexts.contains(new String(ciphertext, "UTF-8"))) {
        throw new GeneralSecurityException("Encryption is not randomized");
      }
      ciphertexts.add(new String(ciphertext, "UTF-8"));
      byte[] decrypted = hybridDecrypt.decrypt(ciphertext, context);
      assertArrayEquals(plaintext, decrypted);
    }
    assertEquals(8, ciphertexts.size());
  }

  @Test
  public void testBasicMultipleEncrypts() throws Exception {
    testBasicMultipleEncrypts(EciesParameters.CurveType.NIST_P256, AES128_CTR_HMAC_SHA256_RAW);
    testBasicMultipleEncrypts(EciesParameters.CurveType.NIST_P384, AES128_CTR_HMAC_SHA256_RAW);
    testBasicMultipleEncrypts(EciesParameters.CurveType.NIST_P521, AES128_CTR_HMAC_SHA256_RAW);

    testBasicMultipleEncrypts(EciesParameters.CurveType.NIST_P521, AES256_SIV_RAW);

    if (!TestUtil.isAndroid()) {
      testBasicMultipleEncrypts(EciesParameters.CurveType.NIST_P256, AES128_GCM_RAW);
      testBasicMultipleEncrypts(EciesParameters.CurveType.NIST_P384, AES128_GCM_RAW);
      testBasicMultipleEncrypts(EciesParameters.CurveType.NIST_P521, AES128_GCM_RAW);
    }
  }
}
