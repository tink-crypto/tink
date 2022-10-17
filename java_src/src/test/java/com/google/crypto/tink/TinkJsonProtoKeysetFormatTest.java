// Copyright 2022 Google LLC
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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.subtle.Hex;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class TinkJsonProtoKeysetFormatTest {

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    MacConfig.register();
    AeadConfig.register();
    SignatureConfig.register();
  }

  private void assertKeysetHandleAreEqual(KeysetHandle keysetHandle1, KeysetHandle keysetHandle2)
      throws Exception {
    // This assertion is too strong, but it works here because we don't parse or serialize
    // keydata.value fields.
    assertThat(CleartextKeysetHandle.getKeyset(keysetHandle2))
        .isEqualTo(CleartextKeysetHandle.getKeyset(keysetHandle1));
  }

  private KeysetHandle generateKeyset() throws GeneralSecurityException {
    return KeysetHandle.newBuilder()
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG")
                .withRandomId()
                .makePrimary())
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG_RAW")
                .withRandomId())
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_256BITTAG")
                .withRandomId()
                .setStatus(KeyStatus.DESTROYED))
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_256BITTAG_RAW")
                .withRandomId()
                .setStatus(KeyStatus.DISABLED))
        .addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId())
        .build();
  }

  private KeysetHandle generatePublicKeyset() throws GeneralSecurityException {
    return KeysetHandle.newBuilder()
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("ECDSA_P256_RAW")
                .withRandomId()
                .setStatus(KeyStatus.DISABLED))
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("ECDSA_P256").withRandomId().makePrimary())
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("ECDSA_P521")
                .withRandomId()
                .setStatus(KeyStatus.DESTROYED))
        .build()
        .getPublicKeysetHandle();
  }

  private Aead generateAead() throws GeneralSecurityException {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES128_CTR_HMAC_SHA256")
                    .withRandomId()
                    .makePrimary())
            .build();
    return handle.getPrimitive(Aead.class);
  }

  @Test
  public void serializeAndParse_successWithSameKeyset() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());
    KeysetHandle parseKeysetHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void serializeKeyset_withoutInsecureSecretKeyAccess_fails() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    assertThrows(
        NullPointerException.class,
        () -> TinkJsonProtoKeysetFormat.serializeKeyset(keysetHandle, null));
  }

  @Test
  public void parseKeyset_withoutInsecureSecretKeyAccess_fails() throws Exception {
    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(generateKeyset(), InsecureSecretKeyAccess.get());

    assertThrows(
        NullPointerException.class,
        () -> TinkJsonProtoKeysetFormat.parseKeyset(serializedKeyset, null));
  }

  @Test
  public void parseInvalidSerializedKeyset_fails() throws Exception {
    String invalidSerializedKeyset = "invalid";
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseKeyset(
                invalidSerializedKeyset, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void serializeEncryptedAndParseEncrypted_successWithSameKeyset() throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData);
    KeysetHandle parseKeysetHandle =
        TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
            serializedKeyset, keyEncryptionAead, associatedData);

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void parseEncryptedKeysetWithInvalidKey_fails() throws Exception {
    Aead keyEncryptionAead = generateAead();
    Aead invalidKeyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset, invalidKeyEncryptionAead, associatedData));
  }

  @Test
  public void parseEncryptedKeysetWithInvalidAssociatedData_fails() throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, "associatedData".getBytes(UTF_8));

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset, keyEncryptionAead, "invalidAssociatedData".getBytes(UTF_8)));
  }

  @Test
  public void serializeAndParseWithoutSecret_successWithSameKeyset() throws Exception {
    KeysetHandle publicKeysetHandle = generatePublicKeyset();

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(publicKeysetHandle);
    KeysetHandle parsePublicKeysetHandle =
        TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset);

    assertKeysetHandleAreEqual(publicKeysetHandle, parsePublicKeysetHandle);
  }

  @Test
  public void serializeWithoutSecret_keysetWithSecretKeys_fails() throws Exception {
    KeysetHandle secretKeysetHandle = generateKeyset();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(secretKeysetHandle));
  }

  @Test
  public void parseWithoutSecret_keysetWithSecretKeys_fails() throws Exception {
    KeysetHandle secretKeysetHandle = generateKeyset();
    String serializedSecretKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(
            secretKeysetHandle, InsecureSecretKeyAccess.get());

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(serializedSecretKeyset));
  }

  @Test
  public void parseWithoutSecretInvalidSerializedKeyset_fails() throws Exception {
    String invalidSerializedKeyset = "invalid";
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(invalidSerializedKeyset));
  }

  @Test
  public void serializeKeyset_worksWithCleartextKeysetHandleReadAndJsonKeysetReader()
      throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());

    KeysetHandle parseKeysetHandle =
        CleartextKeysetHandle.read(JsonKeysetReader.withString(serializedKeyset));

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void parseKeyset_worksWithCleartextKeysetHandleWriteAndJsonKeysetWriter()
      throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withOutputStream(outputStream));
    String serializedKeyset = new String(outputStream.toByteArray(), UTF_8);

    KeysetHandle parseKeysetHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void serializeKeysetWithoutSecret_worksWithKeysetHandleReadNoSecretAndJsonKeysetReader()
      throws Exception {
    KeysetHandle publicKeysetHandle = generatePublicKeyset();

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(publicKeysetHandle);

    KeysetHandle parsePublicKeysetHandle =
        KeysetHandle.readNoSecret(JsonKeysetReader.withString(serializedKeyset));

    assertKeysetHandleAreEqual(publicKeysetHandle, parsePublicKeysetHandle);
  }

  @Test
  public void parseKeysetWithoutSecret_worksWithKeysetHandleWriteNoSecretAndJsonKeysetWriter()
      throws Exception {
    KeysetHandle publicKeysetHandle = generatePublicKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    publicKeysetHandle.writeNoSecret(JsonKeysetWriter.withOutputStream(outputStream));
    String serializedKeyset = new String(outputStream.toByteArray(), UTF_8);

    KeysetHandle parsePublicKeysetHandle =
        TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset);

    assertKeysetHandleAreEqual(publicKeysetHandle, parsePublicKeysetHandle);
  }

  @Test
  public void serializeEncrypted_worksWithKeysetHandleReadWithAssociatedDataAndJsonKeysetReader()
      throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData);

    KeysetHandle parseKeysetHandle =
        KeysetHandle.readWithAssociatedData(
            JsonKeysetReader.withString(serializedKeyset), keyEncryptionAead, associatedData);

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void parseEncrypted_worksWithKeysetHandleWriteWithAssociatedDataAndJsonKeysetWriter()
      throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    keysetHandle.writeWithAssociatedData(
        JsonKeysetWriter.withOutputStream(outputStream), keyEncryptionAead, associatedData);
    String serializedKeyset = new String(outputStream.toByteArray(), UTF_8);

    KeysetHandle parseKeysetHandle =
        TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
            serializedKeyset, keyEncryptionAead, associatedData);

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void parseKeysetFromTestVector()
      throws Exception {
    // The same key as in JsonKeysetReaderTest.
    String serializedKeyset =
        "{"
            + "\"primaryKeyId\": 547623039,"
            + "\"key\": [{"
            + "\"keyData\": {"
            + "\"typeUrl\": \"type.googleapis.com/google.crypto.tink.HmacKey\","
            + "\"keyMaterialType\": \"SYMMETRIC\","
            + "\"value\": \"EgQIAxAQGiBYhMkitTWFVefTIBg6kpvac+bwFOGSkENGmU+1EYgocg==\""
            + "},"
            + "\"outputPrefixType\": \"TINK\","
            + "\"keyId\": 547623039,"
            + "\"status\": \"ENABLED\""
            + "}]}";
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    Mac mac = handle.getPrimitive(Mac.class);
    mac.verifyMac(Hex.decode("0120a4107f3549e4fb3137415a63f5c8a0524f8ca7"), "data".getBytes(UTF_8));
  }

  @Test
  public void parseEncryptedKeysetFromTestVector() throws Exception {
    // This is the same test vector as in KeysetHandleTest.
    // An AEAD key, with which we encrypted the mac keyset below.
    byte[] serializedKeysetEncryptionKeyset =
        Hex.decode(
            "08b891f5a20412580a4c0a30747970652e676f6f676c65617069732e636f6d2f676f6f676c652e6372797"
                + "0746f2e74696e6b2e4165734561784b65791216120208101a10e5d7d0cdd649e81e7952260689b2"
                + "e1971801100118b891f5a2042001");
    KeysetHandle keysetEncryptionHandle = TinkProtoKeysetFormat.parseKeyset(
        serializedKeysetEncryptionKeyset, InsecureSecretKeyAccess.get());
    Aead keysetEncryptionAead = keysetEncryptionHandle.getPrimitive(Aead.class);

    // A keyset that contains one HMAC key, encrypted with the above, using associatedData
    String encryptedKeyset =
        "{\"encryptedKeyset\":"
            + "\"AURdSLhZcFEgMBptDyi4/D8hL3h+Iz7ICgLrdeVRH26Fi3uSeewFoFA5cV5wfNueme3/BBR60yJ4hGpQ"
            + "p+/248ZIgfuWyfmAGZ4dmYnYC1qd/IWkZZfVr3aOsx4j4kFZHkkvA+XIZUh/INbdPsMUNJy9cmu6s8osdH"
            + "zu0XzP2ltWUowbr0fLQJwy92eAvU6gv91k6Tc=\","
            + "\"keysetInfo\":{\"primaryKeyId\":547623039,\"keyInfo\":[{\"typeUrl\":"
            + "\"type.googleapis.com/google.crypto.tink.HmacKey\",\"status\":\"ENABLED\","
            + "\"keyId\":547623039,\"outputPrefixType\":\"TINK\"}]}}";
    byte[] associatedData = Hex.decode("abcdef330012");

    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
            encryptedKeyset, keysetEncryptionAead, associatedData);

    Mac mac = handle.getPrimitive(Mac.class);
    byte[] data = "data".getBytes(UTF_8);
    byte[] tag = Hex.decode("0120a4107f3549e4fb3137415a63f5c8a0524f8ca7");
    mac.verifyMac(tag, data);
  }
}
