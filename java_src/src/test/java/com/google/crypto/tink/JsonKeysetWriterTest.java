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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.subtle.Random;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for JsonKeysetWriter. */
@RunWith(JUnit4.class)
public class JsonKeysetWriterTest {
  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    Config.register(TinkConfig.TINK_1_0_0);
  }

  private void assertKeysetHandle(KeysetHandle handle1, KeysetHandle handle2) throws Exception {
    Mac mac1 = handle1.getPrimitive(Mac.class);
    Mac mac2 = handle2.getPrimitive(Mac.class);
    byte[] message = Random.randBytes(20);

    assertThat(handle2.getKeyset()).isEqualTo(handle1.getKeyset());
    mac2.verifyMac(mac1.computeMac(message), message);
  }

  private void testWrite_shouldWork(KeysetHandle handle1) throws Exception {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(handle1, JsonKeysetWriter.withOutputStream(outputStream));
    KeysetHandle handle2 =
        CleartextKeysetHandle.read(
            JsonKeysetReader.withInputStream(new ByteArrayInputStream(outputStream.toByteArray())));

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testWrite_singleKey_shouldWork() throws Exception {
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    KeysetHandle handle1 = KeysetHandle.generateNew(template);

    testWrite_shouldWork(handle1);
  }

  @Test
  public void testWrite_multipleKeys_shouldWork() throws Exception {
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    KeysetHandle handle1 =
        KeysetManager.withEmptyKeyset()
            .rotate(template)
            .add(template)
            .add(template)
            .getKeysetHandle();

    testWrite_shouldWork(handle1);
  }

  private void testWriteEncrypted_shouldWork(KeysetHandle handle1) throws Exception {
    // Encrypt the keyset with an AeadKey.
    KeyTemplate masterKeyTemplate = AeadKeyTemplates.AES128_EAX;
    Aead masterKey = Registry.getPrimitive(Registry.newKeyData(masterKeyTemplate));
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    handle1.write(JsonKeysetWriter.withOutputStream(outputStream), masterKey);
    KeysetHandle handle2 =
        KeysetHandle.read(
            JsonKeysetReader.withInputStream(new ByteArrayInputStream(outputStream.toByteArray())),
            masterKey);

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testWriteEncrypted_singleKey_shouldWork() throws Exception {
    // Encrypt the keyset with an AeadKey.
    KeysetHandle handle1 = KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_128BITTAG);

    testWriteEncrypted_shouldWork(handle1);
  }

  @Test
  public void testWriteEncrypted_multipleKeys_shouldWork() throws Exception {
    // Encrypt the keyset with an AeadKey.
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    KeysetHandle handle1 =
        KeysetManager.withEmptyKeyset()
            .rotate(template)
            .add(template)
            .add(template)
            .getKeysetHandle();

    testWriteEncrypted_shouldWork(handle1);
  }

  @Test
  public void testWrite_writesNegativeIdAsPositive() throws Exception {
    int magicKeyId = -19230912;
    Keyset unmodified =
        CleartextKeysetHandle.getKeyset(
            KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_128BITTAG));
    Keyset modified =
        Keyset.newBuilder(unmodified)
            .setPrimaryKeyId(magicKeyId)
            .setKey(0, Keyset.Key.newBuilder(unmodified.getKey(0)).setKeyId(magicKeyId).build())
            .build();
    KeysetHandle modifiedHandle = CleartextKeysetHandle.parseFrom(modified.toByteArray());

    // Write cleartext keyset
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(modifiedHandle, JsonKeysetWriter.withOutputStream(outputStream));
    String cleartextKeysetInJson = new String(outputStream.toByteArray(), UTF_8);

    assertThat(cleartextKeysetInJson).contains("\"primaryKeyId\":4275736384");
    assertThat(cleartextKeysetInJson).contains("\"keyId\":4275736384");

    // Write encrypted keyset
    Aead keysetEncryptionAead =
        KeysetHandle.generateNew(KeyTemplates.get("AES128_EAX")).getPrimitive(Aead.class);
    ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream();
    modifiedHandle.write(JsonKeysetWriter.withOutputStream(outputStream2), keysetEncryptionAead);
    String encryptedKeysetInJson = new String(outputStream2.toByteArray(), UTF_8);

    assertThat(encryptedKeysetInJson).contains("\"primaryKeyId\":4275736384");
    assertThat(encryptedKeysetInJson).contains("\"keyId\":4275736384");
  }

}
