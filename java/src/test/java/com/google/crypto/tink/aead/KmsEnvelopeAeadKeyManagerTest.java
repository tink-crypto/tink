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

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Config;
import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKey;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKeyFormat;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
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
  @BeforeClass
  public static void setUp() throws Exception {
    KmsClients.add(new GcpKmsClient()
        .withCredentials(TestUtil.SERVICE_ACCOUNT_FILE));
    Config.register(AeadConfig.TINK_1_0_0);
  }

  @Test
  public void testGcpKmsKeyRestricted() throws Exception {
    KeyTemplate dekTemplate = AeadKeyTemplates.AES128_CTR_HMAC_SHA256;
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        AeadKeyTemplates.createKmsEnvelopeAeadKeyTemplate(
            TestUtil.RESTRICTED_CRYPTO_KEY_URI, dekTemplate));
    TestUtil.runBasicAeadFactoryTests(keysetHandle);
  }

  @Test
  public void testParsingInvalidCiphertexts() throws Exception {
    KeyTemplate dekTemplate = AeadKeyTemplates.AES128_CTR_HMAC_SHA256;
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        AeadKeyTemplates.createKmsEnvelopeAeadKeyTemplate(
            TestUtil.RESTRICTED_CRYPTO_KEY_URI, dekTemplate));

    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = Random.randBytes(20);
    byte[] aad = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, aad);
    ByteBuffer buffer = ByteBuffer.wrap(ciphertext);
    // Skip Tink's header.
    byte[] header = new byte[CryptoFormat.NON_RAW_PREFIX_SIZE];
    buffer.get(header, 0, header.length);
    int encryptedDekSize = buffer.getInt();
    byte[] encryptedDek = new byte[encryptedDekSize];
    buffer.get(encryptedDek, 0, encryptedDekSize);
    byte[] payload = new byte[buffer.remaining()];
    buffer.get(payload, 0, buffer.remaining());

    // valid, should work
    byte[] ciphertext2 = ByteBuffer.allocate(ciphertext.length)
        .put(header)
        .putInt(encryptedDekSize)
        .put(encryptedDek)
        .put(payload)
        .array();
    assertArrayEquals(plaintext, aead.decrypt(ciphertext2, aad));

    // negative length
    ciphertext2 = ByteBuffer.allocate(ciphertext.length)
        .put(header)
        .putInt(-1)
        .put(encryptedDek)
        .put(payload)
        .array();
    try {
      aead.decrypt(ciphertext2, aad);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "decryption failed");
    }

    // length larger than actual value
    ciphertext2 = ByteBuffer.allocate(ciphertext.length)
        .put(header)
        .putInt(encryptedDek.length + 1)
        .put(encryptedDek)
        .put(payload)
        .array();
    try {
      aead.decrypt(ciphertext2, aad);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "decryption failed");
    }

    // length larger than total ciphertext length
    ciphertext2 = ByteBuffer.allocate(ciphertext.length)
        .put(header)
        .putInt(encryptedDek.length + payload.length + 1)
        .put(encryptedDek)
        .put(payload)
        .array();
    try {
      aead.decrypt(ciphertext2, aad);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "decryption failed");
    }
  }

  @Test
  public void testJsonExportAndImport() throws Exception {
    KmsEnvelopeAeadKeyManager keyManager = new KmsEnvelopeAeadKeyManager();
    int keyCount = 4;

    // Prepare example formats and keys.
    ByteString[] formats = new ByteString[keyCount];
    formats[0] = AeadKeyTemplates.createKmsEnvelopeAeadKeyTemplate(
        AesEaxKeyManager.TYPE_URL, AeadKeyTemplates.AES128_EAX).getValue();
    formats[1] = AeadKeyTemplates.createKmsEnvelopeAeadKeyTemplate(
        AesEaxKeyManager.TYPE_URL, AeadKeyTemplates.AES256_EAX).getValue();
    formats[2] = AeadKeyTemplates.createKmsEnvelopeAeadKeyTemplate(
        AesGcmKeyManager.TYPE_URL, AeadKeyTemplates.AES128_GCM).getValue();
    formats[3] = AeadKeyTemplates.createKmsEnvelopeAeadKeyTemplate(
        AesCtrHmacAeadKeyManager.TYPE_URL, AeadKeyTemplates.AES256_CTR_HMAC_SHA256).getValue();

    KmsEnvelopeAeadKey[] keys = new KmsEnvelopeAeadKey[keyCount];
    for (int i = 0; i < keyCount; i++) {
      try {
        keys[i] = (KmsEnvelopeAeadKey) keyManager.newKey(formats[i]);
      } catch (Exception e) {
        throw new Exception(e.toString()
            + "\nFailed for formats[" + i + "]: " + formats[i].toString());
      }
    }

    // Check export and import of keys.
    int count = 0;
    for (KmsEnvelopeAeadKey key : keys) {
      try {
        byte[] json = keyManager.keyToJson(key.toByteString());
        KmsEnvelopeAeadKey keyFromJson = (KmsEnvelopeAeadKey) keyManager.jsonToKey(json);
        assertEquals(key.toString(), keyFromJson.toString());
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for key: " + key.toString());
      }
      count++;
    }
    assertEquals(keyCount, count);

    // Check export and import of key formats.
    count = 0;
    for (ByteString format : formats) {
      try {
        byte[] json = keyManager.keyFormatToJson(format);
        KmsEnvelopeAeadKeyFormat formatFromJson =
            (KmsEnvelopeAeadKeyFormat) keyManager.jsonToKeyFormat(json);
        assertEquals(KmsEnvelopeAeadKeyFormat.parseFrom(format).toString(),
            formatFromJson.toString());
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for format: "
            + KmsEnvelopeAeadKeyFormat.parseFrom(format).toString());
      }
      count++;
    }
    assertEquals(keyCount, count);
  }

  @Test
  @SuppressWarnings("unused")  // Unused key/format/json-variables are not set unless test fails.
  public void testJsonExportAndImportErrors() throws Exception {
    KmsEnvelopeAeadKeyManager keyManager = new KmsEnvelopeAeadKeyManager();

    try {
      byte[] json = "some bad JSON key".getBytes(Util.UTF_8);
      KmsEnvelopeAeadKey key = (KmsEnvelopeAeadKey) keyManager.jsonToKey(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {
      byte[] json = "a bad JSON keyformat".getBytes(Util.UTF_8);
      KmsEnvelopeAeadKeyFormat format = (KmsEnvelopeAeadKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {  // An incomplete JSON key.
      byte[] json = ("{\"version\": 0}").getBytes(Util.UTF_8);
      KmsEnvelopeAeadKey key = (KmsEnvelopeAeadKey) keyManager.jsonToKey(json);
      fail("Incomplet JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // An incomplete JSON key format.
      byte[] json = ("{\"kekUri\": \"some URI\"}").getBytes(Util.UTF_8);
      KmsEnvelopeAeadKeyFormat format = (KmsEnvelopeAeadKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Incomplete JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Extra name in JSON key.
      byte[] json = ("{\"version\": 0, \"params\": {\"kekUri\": \"some URI\"}, "
          + "\"extraName\": 42}").getBytes(Util.UTF_8);
      KmsEnvelopeAeadKey key = (KmsEnvelopeAeadKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // Extra name JSON key format.
      byte[] json = ("{\"kekUri\": \"some URI\", \"dekTemplate\": { \"typeUrl\": \"type URL\"}, "
          + "\"extraName\": 42}").getBytes(Util.UTF_8);
      KmsEnvelopeAeadKeyFormat format = (KmsEnvelopeAeadKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Invalid JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // An incomplete KmsEnvelopeAeadKey.
      KmsEnvelopeAeadKey key = KmsEnvelopeAeadKey.newBuilder().setVersion(42).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Incomplete KmsEnvelopeAeadKey, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    try {  // An incomplete KmsEnvelopeAeadKeyFormat.
      KmsEnvelopeAeadKeyFormat format = KmsEnvelopeAeadKeyFormat.newBuilder()
          .setKekUri("some URI").build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Incomplete KmsEnvelopeAeadKeyFormat, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    try {  // Wrong serialized key proto.
      KeyData key = KeyData.newBuilder()
          .setTypeUrl("some URL").setValue(ByteString.copyFromUtf8("some value")).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Wrong key proto, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "expected serialized KmsEnvelopeAeadKey");
    }

    try {  // Wrong serialized key format proto.
      KeyData format = KeyData.newBuilder()
          .setTypeUrl("some URL").setValue(ByteString.copyFromUtf8("some value")).build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Wrong key format proto, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "expected serialized KmsEnvelopeAeadKeyFormat");
    }
  }
}
