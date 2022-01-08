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
import static com.google.crypto.tink.testing.KeyTypeManagerTestUtil.testKeyTemplateCompatible;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.proto.ChaCha20Poly1305Key;
import com.google.crypto.tink.proto.ChaCha20Poly1305KeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for ChaCha20Poly1305KeyManager. */
@RunWith(JUnit4.class)
public class ChaCha20Poly1305KeyManagerTest {
  private final ChaCha20Poly1305KeyManager manager = new ChaCha20Poly1305KeyManager();
  private final KeyTypeManager.KeyFactory<ChaCha20Poly1305KeyFormat, ChaCha20Poly1305Key> factory =
      manager.keyFactory();

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
          TestUtil.hexEncode(
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
    assertEquals(new ChaCha20Poly1305KeyManager().getKeyType(), template.getTypeUrl());
    assertEquals(KeyTemplate.OutputPrefixType.TINK, template.getOutputPrefixType());
    ChaCha20Poly1305KeyFormat unused =
        ChaCha20Poly1305KeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());
  }

  @Test
  public void testRawChaCha20Poly1305Template() throws Exception {
    KeyTemplate template = ChaCha20Poly1305KeyManager.rawChaCha20Poly1305Template();
    assertEquals(new ChaCha20Poly1305KeyManager().getKeyType(), template.getTypeUrl());
    assertEquals(KeyTemplate.OutputPrefixType.RAW, template.getOutputPrefixType());
    ChaCha20Poly1305KeyFormat unused =
        ChaCha20Poly1305KeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    testKeyTemplateCompatible(manager, ChaCha20Poly1305KeyManager.chaCha20Poly1305Template());
    testKeyTemplateCompatible(manager, ChaCha20Poly1305KeyManager.rawChaCha20Poly1305Template());
  }

  @Test
  public void testKeyFormats() throws Exception {
    factory.validateKeyFormat(factory.keyFormats().get("CHACHA20_POLY1305").keyFormat);
    factory.validateKeyFormat(factory.keyFormats().get("CHACHA20_POLY1305_RAW").keyFormat);
  }
}
