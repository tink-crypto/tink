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
import static org.junit.Assert.fail;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.TestUtil.BytesMutation;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridEncrypt;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.CurveType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
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

  private void testModifyDecrypt(CurveType curveType, KeyTemplate keyTemplate) throws Exception {
    KeyPair recipientKey = EllipticCurves.generateKeyPair(curveType);
    ECPublicKey recipientPublicKey = (ECPublicKey) recipientKey.getPublic();
    ECPrivateKey recipientPrivateKey = (ECPrivateKey) recipientKey.getPrivate();
    byte[] salt = Random.randBytes(8);
    byte[] plaintext = Random.randBytes(4);
    byte[] context = Random.randBytes(4);
    String hmacAlgo = HybridUtil.toHmacAlgo(HashType.SHA256);
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

    // Modifies ciphertext and makes sure that the decryption failed. This test implicitly checks
    // the modification of public key and the raw ciphertext.
    for (BytesMutation mutation : TestUtil.generateMutations(ciphertext)) {
      try {
        hybridDecrypt.decrypt(mutation.value, context);
        fail(
            String.format(
                "Invalid ciphertext, should have thrown exception: ciphertext = %s,context = %s,"
                    + " description = %s",
                Hex.encode(mutation.value), Hex.encode(context), mutation.description));
      } catch (GeneralSecurityException expected) {
        // Expected
      }
    }

    // Modify context.
    for (BytesMutation mutation : TestUtil.generateMutations(context)) {
      try {
        hybridDecrypt.decrypt(ciphertext, mutation.value);
        fail(
            String.format(
                "Invalid context, should have thrown exception: context = %s, ciphertext = %s,"
                    + " description = %s",
                Hex.encode(mutation.value), Hex.encode(ciphertext), mutation.description));
      } catch (GeneralSecurityException expected) {
        // Expected
      }
    }

    // Modify salt.
    // We exclude tests that modify the length of the salt, since the salt has fixed length and
    // modifying the length may not be detected.
    for (int bytes = 0; bytes < salt.length; bytes++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modifiedSalt = Arrays.copyOf(salt, salt.length);
        modifiedSalt[bytes] ^= (byte) (1 << bit);
        hybridDecrypt =
            new EciesAeadHkdfHybridDecrypt(
                recipientPrivateKey,
                modifiedSalt,
                hmacAlgo,
                EllipticCurves.PointFormatType.UNCOMPRESSED,
                new RegistryEciesAeadHkdfDemHelper(keyTemplate));
        try {
          hybridDecrypt.decrypt(ciphertext, context);
          fail("Invalid salt, should have thrown exception");
        } catch (GeneralSecurityException expected) {
          // Expected
        }
      }
    }
  }

  @Test
  public void testModifyDecrypt() throws Exception {
    testModifyDecrypt(CurveType.NIST_P256, AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
    testModifyDecrypt(CurveType.NIST_P384, AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
    testModifyDecrypt(CurveType.NIST_P521, AeadKeyTemplates.AES128_CTR_HMAC_SHA256);

    testModifyDecrypt(CurveType.NIST_P256, AeadKeyTemplates.AES128_GCM);
    testModifyDecrypt(CurveType.NIST_P384, AeadKeyTemplates.AES128_GCM);
    testModifyDecrypt(CurveType.NIST_P521, AeadKeyTemplates.AES128_GCM);
  }
}
