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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.ChaCha20Poly1305Parameters.Variant;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;
import com.google.crypto.tink.util.SecretBytes;
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
  @Before
  public void register() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager(
                    "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key", Aead.class))
        .isNotNull();
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
