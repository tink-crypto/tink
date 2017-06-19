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

import static junit.framework.Assert.fail;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.ChaCha20Poly1305Key;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.TinkProto.KeyData;
import com.google.crypto.tink.TinkProto.KeyStatusType;
import com.google.crypto.tink.TinkProto.KeyTemplate;
import com.google.crypto.tink.TinkProto.OutputPrefixType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.Cipher;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test for ChaCha20Poly1305KeyManager.
 */
@RunWith(JUnit4.class)
public class ChaCha20Poly1305KeyManagerTest {
  private static final int KEY_SIZE = 32;

  @Before
  public void setUp() throws GeneralSecurityException {
    AeadConfig.registerStandardKeyTypes();
  }

  @Test
  public void testBasic() throws Exception {
    KeysetHandle keysetHandle = CleartextKeysetHandle.generateNew(
        AeadKeyTemplates.CHACHA20_POLY1305);
    TestUtil.runBasicAeadFactoryTests(keysetHandle);
  }

  @Test
  public void testCiphertextSize() throws Exception {
    KeysetHandle keysetHandle = CleartextKeysetHandle.generateNew(
        AeadKeyTemplates.CHACHA20_POLY1305);
    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] associatedData = "associatedData".getBytes("UTF-8");
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertEquals(
        CryptoFormat.NON_RAW_PREFIX_SIZE + 12 /* IV_SIZE */ + plaintext.length + 16 /* TAG_SIZE */,
        ciphertext.length);
  }

  @Test
  public void testNewKeyMultipleTimes() throws Exception {
    KeyTemplate keyTemplate = AeadKeyTemplates.CHACHA20_POLY1305;
    ChaCha20Poly1305KeyManager keyManager = new ChaCha20Poly1305KeyManager();
    Set<String> keys = new TreeSet<String>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 10;
    for (int i = 0; i < 10; i++) {
      ChaCha20Poly1305Key key = (ChaCha20Poly1305Key) keyManager.newKey(keyTemplate.getValue());
      keys.add(new String(key.getKeyValue().toByteArray(), "UTF-8"));
      assertEquals(32, key.getKeyValue().toByteArray().length);

      KeyData keyData = keyManager.newKeyData(keyTemplate.getValue());
      key = ChaCha20Poly1305Key.parseFrom(keyData.getValue());
      keys.add(new String(key.getKeyValue().toByteArray(), "UTF-8"));
      assertEquals(32, key.getKeyValue().toByteArray().length);
    }
    assertEquals(10 * 2, keys.size());
  }
}
