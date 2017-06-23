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

import static junit.framework.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.EcUtil;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridEncrypt;
import com.google.crypto.tink.subtle.Random;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
 * TODO(przydatek): Add more tests.
 */
@RunWith(JUnit4.class)
public class EciesAeadHkdfHybridEncryptTest {
  @Before
  public void setUp() throws GeneralSecurityException {
    AeadConfig.registerStandardKeyTypes();
  }

  @Test
  public void testBasicMultipleEncrypts() throws Exception {
    ECParameterSpec spec = EcUtil.getCurveSpec(EllipticCurveType.NIST_P256);
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(spec);
    KeyPair recipientKey = keyGen.generateKeyPair();
    ECPublicKey recipientPublicKey = (ECPublicKey) recipientKey.getPublic();
    ECPrivateKey recipientPrivateKey = (ECPrivateKey) recipientKey.getPrivate();
    byte[] salt = "some salt".getBytes("UTF-8");
    byte[] plaintext = Random.randBytes(111);
    byte[] context = "context info".getBytes("UTF-8");
    HashType hkdfHashType = HashType.SHA256;

    KeyTemplate[] keyTemplates = new KeyTemplate[] {
      AeadKeyTemplates.AES128_CTR_HMAC_SHA256,
      AeadKeyTemplates.AES128_GCM,
    };
    for (int i = 0; i < keyTemplates.length; i++) {
      HybridEncrypt hybridEncrypt = new EciesAeadHkdfHybridEncrypt(recipientPublicKey,
          salt, hkdfHashType, EcPointFormat.UNCOMPRESSED,
          new RegistryEciesAeadHkdfDemHelper(keyTemplates[i]));
      HybridDecrypt hybridDecrypt = new EciesAeadHkdfHybridDecrypt(recipientPrivateKey,
          salt, hkdfHashType, EcPointFormat.UNCOMPRESSED,
          new RegistryEciesAeadHkdfDemHelper(keyTemplates[i]));

      // Makes sure that the encryption is randomized.
      Set<String> ciphertexts = new TreeSet<String>();
      for (int j = 0; j < 1024; j++) {
        byte[] ciphertext = hybridEncrypt.encrypt(plaintext, context);
        if (ciphertexts.contains(new String(ciphertext, "UTF-8"))) {
          throw new GeneralSecurityException("Encryption is not randomized");
        }
        ciphertexts.add(new String(ciphertext, "UTF-8"));
        byte[] decrypted = hybridDecrypt.decrypt(ciphertext, context);
        assertArrayEquals(plaintext, decrypted);
      }
      assertEquals(1024, ciphertexts.size());
    }
  }
}
