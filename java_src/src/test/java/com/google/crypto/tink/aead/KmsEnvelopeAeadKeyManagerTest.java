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
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKey;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKeyFormat;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.FakeKmsClient;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@code KmsEnvelopeAead} and {@code KmsEnvelopeAeadKeyManager}.
 */
@RunWith(JUnit4.class)
public class KmsEnvelopeAeadKeyManagerTest {
  private final KmsEnvelopeAeadKeyManager manager = new KmsEnvelopeAeadKeyManager();
  private final KeyTypeManager.KeyFactory<KmsEnvelopeAeadKeyFormat, KmsEnvelopeAeadKey> factory =
      manager.keyFactory();

  @BeforeClass
  public static void setUp() throws Exception {
    KmsClients.add(new FakeKmsClient());
    AeadConfig.register();
  }

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.REMOTE);
  }

  @Test
  public void validateKeyFormat_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(KmsEnvelopeAeadKeyFormat.getDefaultInstance()));
  }

  @Test
  public void validateKeyFormat_noKekUri() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            factory.validateKeyFormat(
                KmsEnvelopeAeadKeyFormat.newBuilder()
                    .setDekTemplate(
                        com.google.crypto.tink.proto.KeyTemplate.newBuilder()
                            .setTypeUrl("foo")
                            .setValue(ByteString.EMPTY)
                            .build())
                    .build()));
  }

  @Test
  public void validateKeyFormat_noDekTemplate() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            factory.validateKeyFormat(
                KmsEnvelopeAeadKeyFormat.newBuilder().setKekUri("foo").build()));
  }

  @Test
  public void createKey() throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();
    KeyTemplate dekTemplate = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template();

    KmsEnvelopeAeadKey key =
        factory.createKey(KmsEnvelopeAeadKeyManager.createKeyFormat(kekUri, dekTemplate));
    Aead aead = manager.getPrimitive(key, Aead.class);

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    assertThat(aead.decrypt(aead.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
  }

  @Test
  public void createKey_multipleKeysWithSameKek() throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();
    KeyTemplate dekTemplate = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template();

    KmsEnvelopeAeadKey key1 =
        factory.createKey(KmsEnvelopeAeadKeyManager.createKeyFormat(kekUri, dekTemplate));
    Aead aead1 = manager.getPrimitive(key1, Aead.class);

    KmsEnvelopeAeadKey key2 =
        factory.createKey(KmsEnvelopeAeadKeyManager.createKeyFormat(kekUri, dekTemplate));
    Aead aead2 = manager.getPrimitive(key2, Aead.class);

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);

    assertThat(aead1.decrypt(aead2.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
  }

  @Test
  public void getPrimitive() throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();
    KeyTemplate dekTemplate = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template();

    KmsEnvelopeAeadKey key =
        factory.createKey(KmsEnvelopeAeadKeyManager.createKeyFormat(kekUri, dekTemplate));
    Aead aead = manager.getPrimitive(key, Aead.class);

    TestUtil.runBasicAeadTests(aead);
  }

  @Test
  public void getPrimitive_parsingInvalidCiphetexts() throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();
    KeyTemplate dekTemplate = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template();

    KmsEnvelopeAeadKey key =
        factory.createKey(KmsEnvelopeAeadKeyManager.createKeyFormat(kekUri, dekTemplate));
    Aead aead = manager.getPrimitive(key, Aead.class);

    byte[] plaintext = Random.randBytes(20);
    byte[] aad = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, aad);
    ByteBuffer buffer = ByteBuffer.wrap(ciphertext);
    int encryptedDekSize = buffer.getInt();
    byte[] encryptedDek = new byte[encryptedDekSize];
    buffer.get(encryptedDek, 0, encryptedDekSize);
    byte[] payload = new byte[buffer.remaining()];
    buffer.get(payload, 0, buffer.remaining());

    // valid, should work
    byte[] ciphertext2 = ByteBuffer.allocate(ciphertext.length)
        .putInt(encryptedDekSize)
        .put(encryptedDek)
        .put(payload)
        .array();
    assertArrayEquals(plaintext, aead.decrypt(ciphertext2, aad));

    // negative length
    byte[] ciphertext3 =
        ByteBuffer.allocate(ciphertext.length)
            .putInt(-1)
            .put(encryptedDek)
            .put(payload)
            .array();
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext3, aad));

    // length larger than actual value
    byte[] ciphertext4 =
        ByteBuffer.allocate(ciphertext.length)
            .putInt(encryptedDek.length + 1)
            .put(encryptedDek)
            .put(payload)
            .array();
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext4, aad));

    // length larger than total ciphertext length
    byte[] ciphertext5 =
        ByteBuffer.allocate(ciphertext.length)
            .putInt(encryptedDek.length + payload.length + 1)
            .put(encryptedDek)
            .put(payload)
            .array();
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext5, aad));
  }

  @Test
  public void createKeyTemplate() throws Exception {
    // Intentionally using "weird" or invalid values for parameters,
    // to test that the function correctly puts them in the resulting template.
    String kekUri = "some example KEK URI";
    KeyTemplate dekTemplate = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template();
    KeyTemplate template = KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, dekTemplate);
    assertThat(new KmsEnvelopeAeadKeyManager().getKeyType()).isEqualTo(template.getTypeUrl());
    assertThat(KeyTemplate.OutputPrefixType.RAW).isEqualTo(template.getOutputPrefixType());

    KmsEnvelopeAeadKeyFormat format =
        KmsEnvelopeAeadKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(kekUri).isEqualTo(format.getKekUri());
    assertThat(dekTemplate.getTypeUrl()).isEqualTo(format.getDekTemplate().getTypeUrl());
    assertThat(dekTemplate.getValue()).isEqualTo(format.getDekTemplate().getValue().toByteArray());
  }

  @Test
  public void createKeyTemplate_multipleKeysWithSameKek() throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();
    KeyTemplate dekTemplate = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template();

    KeyTemplate kt1 = KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, dekTemplate);
    KeysetHandle handle1 = KeysetHandle.generateNew(kt1);
    Aead aead1 = handle1.getPrimitive(Aead.class);

    KeyTemplate kt2 = KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, dekTemplate);
    KeysetHandle handle2 = KeysetHandle.generateNew(kt2);
    Aead aead2 = handle2.getPrimitive(Aead.class);

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);

    assertThat(aead1.decrypt(aead2.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
  }
}
