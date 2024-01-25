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
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters.Variant;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.SlowInputStream;
import com.google.crypto.tink.subtle.XChaCha20Poly1305;
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayInputStream;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Test for XChaCha20Poly1305KeyManager. */
@RunWith(Theories.class)
public class XChaCha20Poly1305KeyManagerTest {
  @Before
  public void register() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager(
                    "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key", Aead.class))
        .isNotNull();
  }

  @Test
  public void testXChaCha20Poly1305Template() throws Exception {
    KeyTemplate template = XChaCha20Poly1305KeyManager.xChaCha20Poly1305Template();
    assertThat(template.toParameters())
        .isEqualTo(XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK));
  }

  @Test
  public void testRawXChaCha20Poly1305Template() throws Exception {
    KeyTemplate template = XChaCha20Poly1305KeyManager.rawXChaCha20Poly1305Template();
    assertThat(template.toParameters()).isEqualTo(XChaCha20Poly1305Parameters.create());
  }

  @Test
  public void testKeyTemplatesWork() throws Exception {
    Parameters p = XChaCha20Poly1305KeyManager.xChaCha20Poly1305Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = XChaCha20Poly1305KeyManager.rawXChaCha20Poly1305Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {"XCHACHA20_POLY1305", "XCHACHA20_POLY1305_RAW"};

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Test
  public void testCreateKeyFromRandomness_tinkVariant_works() throws Exception {
    byte[] keyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
        };
    XChaCha20Poly1305Parameters parameters =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK);
    com.google.crypto.tink.aead.XChaCha20Poly1305Key key =
        XChaCha20Poly1305KeyManager.createXChaChaKeyFromRandomness(
            parameters, new ByteArrayInputStream(keyMaterial), 123, InsecureSecretKeyAccess.get());
    byte[] truncatedKeyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31
        };

    Key expectedKey =
        com.google.crypto.tink.aead.XChaCha20Poly1305Key.create(
            XChaCha20Poly1305Parameters.Variant.TINK,
            SecretBytes.copyFrom(truncatedKeyMaterial, InsecureSecretKeyAccess.get()),
            123);
    assertTrue(key.equalsKey(expectedKey));
  }

  @Test
  public void testCreateKeyFromRandomness_rawVariant_works() throws Exception {
    byte[] keyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
        };
    XChaCha20Poly1305Parameters parameters =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX);
    com.google.crypto.tink.aead.XChaCha20Poly1305Key key =
        XChaCha20Poly1305KeyManager.createXChaChaKeyFromRandomness(
            parameters, new ByteArrayInputStream(keyMaterial), null, InsecureSecretKeyAccess.get());
    byte[] truncatedKeyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31
        };

    Key expectedKey =
        com.google.crypto.tink.aead.XChaCha20Poly1305Key.create(
            XChaCha20Poly1305Parameters.Variant.NO_PREFIX,
            SecretBytes.copyFrom(truncatedKeyMaterial, InsecureSecretKeyAccess.get()),
            null);
    assertTrue(key.equalsKey(expectedKey));
  }

  @Test
  public void testCreateKeyFromRandomness_slowInputStream_works() throws Exception {
    byte[] keyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
        };
    XChaCha20Poly1305Parameters parameters =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK);
    com.google.crypto.tink.aead.XChaCha20Poly1305Key key =
        XChaCha20Poly1305KeyManager.createXChaChaKeyFromRandomness(
            parameters, SlowInputStream.copyFrom(keyMaterial), 1237, InsecureSecretKeyAccess.get());
    byte[] truncatedKeyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31
        };

    Key expectedKey =
        com.google.crypto.tink.aead.XChaCha20Poly1305Key.create(
            XChaCha20Poly1305Parameters.Variant.TINK,
            SecretBytes.copyFrom(truncatedKeyMaterial, InsecureSecretKeyAccess.get()),
            1237);
    assertTrue(key.equalsKey(expectedKey));
  }

  @Test
  public void callingCreateTwiceGivesDifferentKeys() throws Exception {
    Parameters p = XChaCha20Poly1305KeyManager.xChaCha20Poly1305Template().toParameters();
    Key key = KeysetHandle.generateNew(p).getAt(0).getKey();
    for (int i = 0; i < 1000; ++i) {
      assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().equalsKey(key)).isFalse();
    }
  }

  @Test
  public void getPrimitiveKeysetHandle() throws Exception {
    com.google.crypto.tink.aead.XChaCha20Poly1305Key key =
        com.google.crypto.tink.aead.XChaCha20Poly1305Key.create(
            Variant.TINK, SecretBytes.randomBytes(32), 42);
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary()).build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] aad = "aad".getBytes(UTF_8);

    Aead aead = keysetHandle.getPrimitive(Aead.class);
    Aead directAead = XChaCha20Poly1305.create(key);


    assertThat(aead.decrypt(directAead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
    assertThat(directAead.decrypt(aead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
  }
}
