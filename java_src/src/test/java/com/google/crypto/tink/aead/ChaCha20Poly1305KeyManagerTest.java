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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.ChaCha20Poly1305Parameters.Variant;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.ChaCha20Poly1305Key;
import com.google.crypto.tink.proto.ChaCha20Poly1305KeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.TreeSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Test for ChaCha20Poly1305KeyManager. */
@RunWith(Theories.class)
public class ChaCha20Poly1305KeyManagerTest {
  private final ChaCha20Poly1305KeyManager manager = new ChaCha20Poly1305KeyManager();

  @Before
  public void register() throws Exception {
    AeadConfig.register();
  }

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
    assertThrows(
        GeneralSecurityException.class,
        () ->
            new ChaCha20Poly1305KeyManager().validateKey(ChaCha20Poly1305Key.getDefaultInstance()));
  }

  @Test
  public void validateKey_checkAllLengths() throws Exception {
    for (int j = 0; j < 100; j++) {
      final int i = j;
      if (i == 32) {
        manager.validateKey(createChaCha20Poly1305Key(i));
      } else {
        assertThrows(
            GeneralSecurityException.class,
            () -> manager.validateKey(createChaCha20Poly1305Key(i)));
      }
    }
  }

  @Test
  public void validateKey_version() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                ChaCha20Poly1305Key.newBuilder(createChaCha20Poly1305Key(32))
                    .setVersion(1)
                    .build()));
  }

  @Test
  public void createKey_valid() throws Exception {
    manager.validateKey(
        manager.keyFactory().createKey(ChaCha20Poly1305KeyFormat.getDefaultInstance()));
  }

  @Test
  public void createKey_values() throws Exception {
    ChaCha20Poly1305Key key =
        manager.keyFactory().createKey(ChaCha20Poly1305KeyFormat.getDefaultInstance());
    assertThat(key.getVersion()).isEqualTo(0);
    assertThat(key.getKeyValue()).hasSize(32);
  }

  @Test
  public void createKey_multipleCallsCreateDifferentKeys() throws Exception {
    TreeSet<String> keys = new TreeSet<>();
    KeyTypeManager.KeyFactory<ChaCha20Poly1305KeyFormat, ChaCha20Poly1305Key> factory =
        new ChaCha20Poly1305KeyManager().keyFactory();
    final int numKeys = 1000;
    for (int i = 0; i < numKeys; ++i) {
      keys.add(
          Hex.encode(
              factory.createKey(ChaCha20Poly1305KeyFormat.getDefaultInstance()).toByteArray()));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void testCiphertextSize() throws Exception {
    Aead aead =
        new ChaCha20Poly1305KeyManager().getPrimitive(createChaCha20Poly1305Key(32), Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertEquals(12 /* IV_SIZE */ + plaintext.length + 16 /* TAG_SIZE */, ciphertext.length);
  }

  private ChaCha20Poly1305Key createChaCha20Poly1305Key(int keySize) {
    return ChaCha20Poly1305Key.newBuilder()
        .setVersion(0)
        .setKeyValue(ByteString.copyFrom(Random.randBytes(keySize)))
        .build();
  }

  @Test
  public void testChaCha20Poly1305Template() throws Exception {
    KeyTemplate template = ChaCha20Poly1305KeyManager.chaCha20Poly1305Template();
    assertThat(template.toParameters())
        .isEqualTo(ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.TINK));
  }

  @Test
  public void testRawChaCha20Poly1305Template() throws Exception {
    KeyTemplate template = ChaCha20Poly1305KeyManager.rawChaCha20Poly1305Template();
    assertThat(template.toParameters()).isEqualTo(ChaCha20Poly1305Parameters.create());
  }

  @Test
  public void testKeyTemplatesWork() throws Exception {
    Parameters p = ChaCha20Poly1305KeyManager.chaCha20Poly1305Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = ChaCha20Poly1305KeyManager.rawChaCha20Poly1305Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {"CHACHA20_POLY1305", "CHACHA20_POLY1305_RAW"};

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Test
  public void callingCreateTwiceGivesDifferentKeys() throws Exception {
    Parameters p = ChaCha20Poly1305KeyManager.chaCha20Poly1305Template().toParameters();
    Key key = KeysetHandle.generateNew(p).getAt(0).getKey();
    for (int i = 0; i < 1000; ++i) {
      assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().equalsKey(key)).isFalse();
    }
  }

  @Test
  public void getPrimitiveKeysetHandle() throws Exception {
    com.google.crypto.tink.aead.ChaCha20Poly1305Key key =
        com.google.crypto.tink.aead.ChaCha20Poly1305Key.create(
            Variant.TINK, SecretBytes.randomBytes(32), 42);
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary()).build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] aad = "aad".getBytes(UTF_8);

    Aead aead = keysetHandle.getPrimitive(Aead.class);
    Aead directAead = ChaCha20Poly1305.create(key);

    assertThat(aead.decrypt(directAead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
    assertThat(directAead.decrypt(aead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
  }
}
