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

package com.google.cloud.crypto.tink.aead;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.Aead;
import com.google.cloud.crypto.tink.CryptoFormat;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.TestUtil;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.Test;

public class AesCtrHmacAeadKeyTest {

  @Test
  public void testBasic() throws Exception {
    AeadFactory.registerStandardKeyTypes();
    String aesCtrKeyValue = "0123456789abcdef";
    String hmacKeyValue = "0123456789123456";
    int ivSize = 12;
    int tagSize = 16;
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createAesCtrHmacAeadKey(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK)));
    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] associatedData = "associatedData".getBytes("UTF-8");
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);

    assertArrayEquals(plaintext, aead.decrypt(ciphertext, associatedData));
    assertEquals(
        CryptoFormat.NON_RAW_PREFIX_SIZE + plaintext.length  + ivSize + tagSize,
        ciphertext.length);

    byte original = ciphertext[0];
    ciphertext[0] = (byte) ~original;
    try {
      aead.decrypt(ciphertext, associatedData);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("decrypted failed"));
    }

    ciphertext[0] = original;
    original = ciphertext[CryptoFormat.NON_RAW_PREFIX_SIZE];
    ciphertext[CryptoFormat.NON_RAW_PREFIX_SIZE] = (byte) ~original;
    try {
      aead.decrypt(ciphertext, associatedData);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("decrypted failed"));
    }

    ciphertext[0] = original;
    original = associatedData[0];
    associatedData[0] = (byte) ~original;
    try {
      aead.decrypt(ciphertext, associatedData);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("decrypted failed"));
    }
  }
}
