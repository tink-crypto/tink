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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.proto.ChaCha20Poly1305Key;
import com.google.crypto.tink.proto.ChaCha20Poly1305KeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for ChaCha20Poly1305KeyManager. */
@RunWith(JUnit4.class)
public class ChaCha20Poly1305KeyManagerTest {
  @Test
  public void basics() throws Exception {
    assertThat(new ChaCha20Poly1305KeyManager().getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key");
    assertThat(new ChaCha20Poly1305KeyManager().getVersion()).isEqualTo(0);
    assertThat(new ChaCha20Poly1305KeyManager().keyMaterialType())
        .isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void validateKeyFormat() throws Exception {
    new ChaCha20Poly1305KeyManager()
        .keyFactory()
        .validateKeyFormat(ChaCha20Poly1305KeyFormat.getDefaultInstance());
  }


  @Test
  public void validateKey_empty() throws Exception {
    try {
      new ChaCha20Poly1305KeyManager().validateKey(ChaCha20Poly1305Key.getDefaultInstance());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKey_checkAllLengths() throws Exception {
    ChaCha20Poly1305KeyManager manager = new ChaCha20Poly1305KeyManager();
    for (int i = 0; i < 100; i++) {
      if (i == 32) {
        manager.validateKey(createChaCha20Poly1305Key(i));
      } else {
        try {
          manager.validateKey(createChaCha20Poly1305Key(i));
          fail();
        } catch (GeneralSecurityException e) {
          // expected
        }
      }
    }
  }

  @Test
  public void validateKey_version() throws Exception {
    ChaCha20Poly1305KeyManager manager = new ChaCha20Poly1305KeyManager();

    try {
      manager.validateKey(
          ChaCha20Poly1305Key.newBuilder(createChaCha20Poly1305Key(32)).setVersion(1).build());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void createKey_valid() throws Exception {
    ChaCha20Poly1305KeyManager manager = new ChaCha20Poly1305KeyManager();
    manager.validateKey(
        manager.keyFactory().createKey(ChaCha20Poly1305KeyFormat.getDefaultInstance()));
  }

  @Test
  public void createKey_values() throws Exception {
    ChaCha20Poly1305KeyManager manager = new ChaCha20Poly1305KeyManager();
    ChaCha20Poly1305Key key =
        manager.keyFactory().createKey(ChaCha20Poly1305KeyFormat.getDefaultInstance());
    assertThat(key.getVersion()).isEqualTo(0);
    assertThat(key.getKeyValue()).hasSize(32);
  }

  @Test
  public void createKey_multipleCallsCreateDifferentKeys() throws Exception {
    TreeSet<String> keys = new TreeSet<>();
    ChaCha20Poly1305KeyManager.KeyFactory<ChaCha20Poly1305KeyFormat, ChaCha20Poly1305Key> factory =
        new ChaCha20Poly1305KeyManager().keyFactory();
    final int numKeys = 1000;
    for (int i = 0; i < numKeys; ++i) {
      keys.add(
          TestUtil.hexEncode(
              factory.createKey(ChaCha20Poly1305KeyFormat.getDefaultInstance()).toByteArray()));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void testCiphertextSize() throws Exception {
    Aead aead =
        new ChaCha20Poly1305KeyManager().getPrimitive(createChaCha20Poly1305Key(32), Aead.class);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] associatedData = "associatedData".getBytes("UTF-8");
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertEquals(12 /* IV_SIZE */ + plaintext.length + 16 /* TAG_SIZE */, ciphertext.length);
  }

  private ChaCha20Poly1305Key createChaCha20Poly1305Key(int keySize) {
    return ChaCha20Poly1305Key.newBuilder()
        .setVersion(0)
        .setKeyValue(ByteString.copyFrom(Random.randBytes(keySize)))
        .build();
  }
}
