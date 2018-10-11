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

package com.google.crypto.tink.aead;

import static org.junit.Assert.assertEquals;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.XChaCha20Poly1305Key;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for XChaCha20Poly1305KeyManager. */
@RunWith(JUnit4.class)
public class XChaCha20Poly1305KeyManagerTest {
  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    AeadConfig.register();
  }

  @Test
  public void testBasic() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.XCHACHA20_POLY1305);
    TestUtil.runBasicAeadFactoryTests(keysetHandle);
  }

  @Test
  public void testCiphertextSize() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.XCHACHA20_POLY1305);
    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] associatedData = "associatedData".getBytes("UTF-8");
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertEquals(
        CryptoFormat.NON_RAW_PREFIX_SIZE + 24 /* IV_SIZE */ + plaintext.length + 16 /* TAG_SIZE */,
        ciphertext.length);
  }

  @Test
  public void testNewKeyMultipleTimes() throws Exception {
    KeyTemplate keyTemplate = AeadKeyTemplates.XCHACHA20_POLY1305;
    XChaCha20Poly1305KeyManager keyManager = new XChaCha20Poly1305KeyManager();
    Set<String> keys = new TreeSet<String>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 10;
    for (int i = 0; i < numTests; i++) {
      XChaCha20Poly1305Key key = (XChaCha20Poly1305Key) keyManager.newKey(keyTemplate.getValue());
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(32, key.getKeyValue().toByteArray().length);

      KeyData keyData = keyManager.newKeyData(keyTemplate.getValue());
      key = XChaCha20Poly1305Key.parseFrom(keyData.getValue());
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(32, key.getKeyValue().toByteArray().length);
    }
    assertEquals(numTests * 2, keys.size());
  }
}
