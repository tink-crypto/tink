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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.AesCtrKeyFormat;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesCtrJceCipher;
import com.google.crypto.tink.subtle.IndCpaCipher;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link AesCtrKeyManager}. */
@RunWith(JUnit4.class)
public class AesCtrKeyManagerTest {
  private final AesCtrKeyManager manager = new AesCtrKeyManager();
  private final KeyTypeManager.KeyFactory<AesCtrKeyFormat, AesCtrKey> factory =
      manager.keyFactory();

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType()).isEqualTo("type.googleapis.com/google.crypto.tink.AesCtrKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void validateKeyFormat_empty_invalid() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesCtrKeyFormat.getDefaultInstance()));
  }

  private AesCtrKeyFormat createFormat(int ivSize, int keySize) {
    return AesCtrKeyFormat.newBuilder()
        .setParams(AesCtrParams.newBuilder().setIvSize(ivSize).build())
        .setKeySize(keySize)
        .build();
  }

  @Test
  public void createKey_valid() throws Exception {
    factory.validateKeyFormat(createFormat(12, 16));
    factory.validateKeyFormat(createFormat(13, 16));
    factory.validateKeyFormat(createFormat(14, 16));
    factory.validateKeyFormat(createFormat(15, 16));
    factory.validateKeyFormat(createFormat(16, 16));

    factory.validateKeyFormat(createFormat(12, 32));
    factory.validateKeyFormat(createFormat(13, 32));
    factory.validateKeyFormat(createFormat(14, 32));
    factory.validateKeyFormat(createFormat(15, 32));
    factory.validateKeyFormat(createFormat(16, 32));
  }

  @Test
  public void createKey_smallIv_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> factory.validateKeyFormat(createFormat(11, 16)));
  }

  @Test
  public void createKey_bigIv_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> factory.validateKeyFormat(createFormat(17, 16)));
  }

  @Test
  public void createKey_8ByteAesKey_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> factory.validateKeyFormat(createFormat(16, 8)));
  }

  @Test
  public void createKey_15ByteAesKey_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> factory.validateKeyFormat(createFormat(16, 15)));
  }

  @Test
  public void createKey_17ByteAesKey_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> factory.validateKeyFormat(createFormat(16, 17)));
  }

  @Test
  public void createKey_correctVersion() throws Exception {
    assertThat(factory.createKey(createFormat(16, 16)).getVersion()).isEqualTo(0);
  }

  @Test
  public void createKey_keySize() throws Exception {
    assertThat(factory.createKey(createFormat(16, 16)).getKeyValue()).hasSize(16);
    assertThat(factory.createKey(createFormat(16, 32)).getKeyValue()).hasSize(32);
  }

  @Test
  public void createKey_multipleCallsCreateDifferentKeys() throws Exception {
    Set<String> keys = new TreeSet<>();
    final int numKeys = 100;
    for (int i = 0; i < numKeys; ++i) {
      keys.add(
          TestUtil.hexEncode(factory.createKey(createFormat(16, 16)).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void getPrimitive() throws Exception {
    AesCtrKey key = factory.createKey(createFormat(14, 32));
    IndCpaCipher managerCipher = manager.getPrimitive(key, IndCpaCipher.class);
    IndCpaCipher directCipher = new AesCtrJceCipher(key.getKeyValue().toByteArray(), 14);

    byte[] plaintext = Random.randBytes(20);
    assertThat(directCipher.decrypt(managerCipher.encrypt(plaintext))).isEqualTo(plaintext);
  }
}
