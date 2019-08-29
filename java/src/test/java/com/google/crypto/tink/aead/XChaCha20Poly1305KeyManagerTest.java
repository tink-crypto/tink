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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.XChaCha20Poly1305Key;
import com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.XChaCha20Poly1305;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for XChaCha20Poly1305KeyManager. */
@RunWith(JUnit4.class)
public class XChaCha20Poly1305KeyManagerTest {
  private final XChaCha20Poly1305KeyManager manager = new XChaCha20Poly1305KeyManager();
  private final XChaCha20Poly1305KeyManager.KeyFactory<
          XChaCha20Poly1305KeyFormat, XChaCha20Poly1305Key>
      factory = manager.keyFactory();

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void validateKeyFormat() throws Exception {
    factory.validateKeyFormat(XChaCha20Poly1305KeyFormat.getDefaultInstance());
  }

  @Test
  public void createKey_valid() throws Exception {
    manager.validateKey(factory.createKey(XChaCha20Poly1305KeyFormat.getDefaultInstance()));
  }

  @Test
  public void createKey_correctVersion() throws Exception {
    assertThat(factory.createKey(XChaCha20Poly1305KeyFormat.getDefaultInstance()).getVersion())
        .isEqualTo(0);
  }

  @Test
  public void createKey_keySize() throws Exception {
    assertThat(factory.createKey(XChaCha20Poly1305KeyFormat.getDefaultInstance()).getKeyValue())
        .hasSize(32);
  }

  @Test
  public void createKey_multipleCallsCreateDifferentKeys() throws Exception {
    Set<String> keys = new TreeSet<>();
    final int numKeys = 100;
    for (int i = 0; i < numKeys; ++i) {
      keys.add(
          TestUtil.hexEncode(
              factory
                  .createKey(XChaCha20Poly1305KeyFormat.getDefaultInstance())
                  .getKeyValue()
                  .toByteArray()));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void getPrimitive() throws Exception {
    XChaCha20Poly1305Key key = factory.createKey(XChaCha20Poly1305KeyFormat.getDefaultInstance());
    Aead managerAead = manager.getPrimitive(key, Aead.class);
    Aead directAead = new XChaCha20Poly1305(key.getKeyValue().toByteArray());

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    assertThat(directAead.decrypt(managerAead.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
  }
}
