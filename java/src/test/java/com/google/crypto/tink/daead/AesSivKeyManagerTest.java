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

package com.google.crypto.tink.daead;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.proto.AesSivKey;
import com.google.crypto.tink.proto.AesSivKeyFormat;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.Cipher;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for AesSivKeyManager. */
@RunWith(JUnit4.class)
public class AesSivKeyManagerTest {
  private KeyTemplate[] keyTemplates;

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    DeterministicAeadConfig.register();
  }

  @Before
  public void setUp2() throws Exception {
    if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
      System.out.println(
          "Unlimited Strength Jurisdiction Policy Files are required"
              + " but not installed. Skip all DeterministicAeadFactory tests");
      keyTemplates = new KeyTemplate[] {};
    } else {
      keyTemplates = new KeyTemplate[] {DeterministicAeadKeyTemplates.AES256_SIV};
    }
  }

  @Test
  public void testCiphertextSize() throws Exception {
    for (KeyTemplate template : keyTemplates) {
      KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
      DeterministicAead daead = keysetHandle.getPrimitive(DeterministicAead.class);
      byte[] plaintext = "plaintext".getBytes("UTF-8");
      byte[] associatedData = "associatedData".getBytes("UTF-8");
      byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
      assertEquals(
          CryptoFormat.NON_RAW_PREFIX_SIZE + plaintext.length + 16 /* IV_SIZE */,
          ciphertext.length);
    }
  }

  @Test
  public void testNewKeyMultipleTimes() throws Exception {
    for (KeyTemplate keyTemplate : keyTemplates) {
      AesSivKeyManager keyManager = new AesSivKeyManager();
      Set<String> keys = new TreeSet<String>();
      // Calls newKey multiple times and make sure that they generate different keys.
      int numTests = 10;
      for (int i = 0; i < numTests; i++) {
        AesSivKey key = (AesSivKey) keyManager.newKey(keyTemplate.getValue());
        keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));

        KeyData keyData = keyManager.newKeyData(keyTemplate.getValue());
        key = AesSivKey.parseFrom(keyData.getValue());
        keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      }
      assertEquals(numTests * 2, keys.size());
    }
  }

  @Test
  public void testNewKeyWithInvalidKeyFormats() throws Exception {
    if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
      System.out.println(
          "Unlimited Strength Jurisdiction Policy Files are required"
              + " but not installed. Skip all AesSivKeyManager tests");
      return;
    }

    AesSivKeyManager keyManager = new AesSivKeyManager();

    try {
      // AesSiv doesn't accept 32-byte keys.
      keyManager.newKey(createAesSivKeyFormat(32));
      fail("32-byte keys should not be accepted");
    } catch (InvalidAlgorithmParameterException ex) {
      // expected.
    }

    try {
      // AesSiv doesn't accept 48-byte keys.
      keyManager.newKey(createAesSivKeyFormat(48));
      fail("48-byte keys should not be accepted");
    } catch (InvalidAlgorithmParameterException ex) {
      // expected.
    }

    for (int j = 0; j < 100; j++) {
      if (j == 64) {
        continue;
      }

      try {
        keyManager.newKey(createAesSivKeyFormat(j));
        fail("Keys with invalid size should not be accepted: " + j);
      } catch (InvalidAlgorithmParameterException ex) {
        // expected.
      }
    }
  }

  @Test
  public void testGetPrimitiveWithInvalidKeys() throws Exception {
    if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
      System.out.println(
          "Unlimited Strength Jurisdiction Policy Files are required"
              + " but not installed. Skip all AesSivKeyManager tests");
      return;
    }
    AesSivKeyManager keyManager = new AesSivKeyManager();

    try {
      keyManager.getPrimitive(createAesSivKey(32));
      fail("32-byte keys should not be accepted");
    } catch (InvalidKeyException ex) {
      // expected.
    }

    try {
      keyManager.getPrimitive(createAesSivKey(48));
      fail("48-byte keys should not be accepted");
    } catch (InvalidKeyException ex) {
      // expected.
    }

    for (int j = 0; j < 100; j++) {
      if (j == 64) {
        continue;
      }

      try {
        keyManager.getPrimitive(createAesSivKey(j));
        fail("Keys with invalid size should not be accepted: " + j);
      } catch (InvalidKeyException ex) {
        // expected.
      }
    }
  }

  private AesSivKeyFormat createAesSivKeyFormat(int keySize) {
    return AesSivKeyFormat.newBuilder().setKeySize(keySize).build();
  }

  private AesSivKey createAesSivKey(int keySize) {
    return AesSivKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(keySize)))
        .build();
  }
}
