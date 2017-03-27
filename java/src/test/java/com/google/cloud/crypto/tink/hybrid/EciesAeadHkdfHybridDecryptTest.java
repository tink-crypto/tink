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

package com.google.cloud.crypto.tink.hybrid;

import static junit.framework.Assert.fail;
import static org.junit.Assert.assertArrayEquals;

import com.google.cloud.crypto.tink.CommonProto.EcPointFormat;
import com.google.cloud.crypto.tink.CommonProto.EllipticCurveType;
import com.google.cloud.crypto.tink.HybridDecrypt;
import com.google.cloud.crypto.tink.HybridEncrypt;
import com.google.cloud.crypto.tink.TestUtil;
import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.cloud.crypto.tink.Util;
import com.google.cloud.crypto.tink.aead.AeadFactory;
import com.google.cloud.crypto.tink.subtle.Random;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
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
    AeadFactory.registerStandardKeyTypes();
  }

  @Test
  public void testModifyDecrypt() throws Exception {
    ECParameterSpec spec = Util.getCurveSpec(EllipticCurveType.NIST_P256);
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(spec);
    KeyPair recipientKey = keyGen.generateKeyPair();
    ECPublicKey recipientPublicKey = (ECPublicKey) recipientKey.getPublic();
    ECPrivateKey recipientPrivateKey = (ECPrivateKey) recipientKey.getPrivate();
    byte[] salt = Random.randBytes(123);
    byte[] plaintext = Random.randBytes(111);
    byte[] context = "context info".getBytes("UTF-8");
    String hmacAlgo = "HmacSha256";

    KeyTemplate[] keyTemplates = new KeyTemplate[] {
      TestUtil.createAesCtrHmacAeadKeyTemplate(16, 16, 16, 16),
      TestUtil.createAesGcmKeyTemplate(16)
    };
    for (int i = 0; i < keyTemplates.length; i++) {
      HybridEncrypt hybridEncrypt = new EciesAeadHkdfHybridEncrypt(recipientPublicKey, salt,
          hmacAlgo, keyTemplates[i], EcPointFormat.UNCOMPRESSED);
      HybridDecrypt hybridDecrypt = new EciesAeadHkdfHybridDecrypt(recipientPrivateKey, salt,
          hmacAlgo, keyTemplates[i], EcPointFormat.UNCOMPRESSED);

      byte[] ciphertext = hybridEncrypt.encrypt(plaintext, context);
      byte[] decrypted = hybridDecrypt.decrypt(ciphertext, context);
      assertArrayEquals(plaintext, decrypted);

      // Changes each bit of ciphertext and makes sure that the decryption failed. This test
      // implicitly checks the modification of public key and the raw ciphertext.
      for (int bytes = 0; bytes < ciphertext.length; bytes++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedCiphertext = Arrays.copyOf(ciphertext, ciphertext.length);
          modifiedCiphertext[bytes] ^= (byte) (1 << bit);
          try {
            hybridDecrypt.decrypt(modifiedCiphertext, context);
            fail("Invalid ciphertext, should have thrown exception");
          } catch (GeneralSecurityException expected) {
            // Expected
          }
        }
      }
      // Modify context.
      try {
        hybridDecrypt.decrypt(ciphertext, Arrays.copyOf(context, context.length - 1));
        fail("Invalid context, should have thrown exception");
      } catch (GeneralSecurityException expected) {
        // Expected
      }
      // Modify salt.
      hybridDecrypt = new EciesAeadHkdfHybridDecrypt(recipientPrivateKey,
          Arrays.copyOf(salt, salt.length - 1), hmacAlgo, keyTemplates[i],
          EcPointFormat.UNCOMPRESSED);
      try {
        hybridDecrypt.decrypt(ciphertext, context);
        fail("Invalid salt, should have thrown exception");
      } catch (GeneralSecurityException expected) {
        // Expected
      }
    }
  }
}
