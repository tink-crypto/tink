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
public final class TinkProtoKeysetFormatTest {

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

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());
    KeysetHandle parseKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void serializeKeyset_withoutInsecureSecretKeyAccess_fails() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    assertThrows(
        NullPointerException.class,
        () -> TinkProtoKeysetFormat.serializeKeyset(keysetHandle, null));
  }

  @Test
  public void parseKeyset_withoutInsecureSecretKeyAccess_fails() throws Exception {
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(generateKeyset(), InsecureSecretKeyAccess.get());

    assertThrows(
        NullPointerException.class,
        () -> TinkProtoKeysetFormat.parseKeyset(serializedKeyset, null));
  }

  @Test
  public void parseInvalidSerializedKeyset_fails() throws Exception {
    byte[] invalidSerializedKeyset = "invalid".getBytes(UTF_8);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseKeyset(
                invalidSerializedKeyset, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void serializeEncryptedAndParseEncrypted_successWithSameKeyset() throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData);
    KeysetHandle parseKeysetHandle =
        TinkProtoKeysetFormat.parseEncryptedKeyset(
            serializedKeyset, keyEncryptionAead, associatedData);

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void parseEncryptedKeysetWithInvalidKey_fails() throws Exception {
    Aead keyEncryptionAead = generateAead();
    Aead invalidKeyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset, invalidKeyEncryptionAead, associatedData));
  }

  @Test
  public void parseEncryptedKeysetWithInvalidAssociatedData_fails() throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, "associatedData".getBytes(UTF_8));

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset, keyEncryptionAead, "invalidAssociatedData".getBytes(UTF_8)));
  }

  @Test
  public void serializeAndParseWithoutSecret_successWithSameKeyset() throws Exception {
    KeysetHandle publicKeysetHandle = generatePublicKeyset();

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeysetWithoutSecret(publicKeysetHandle);
    KeysetHandle parsePublicKeysetHandle =
        TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset);

    assertKeysetHandleAreEqual(publicKeysetHandle, parsePublicKeysetHandle);
  }

  @Test
  public void serializeWithoutSecret_keysetWithSecretKeys_fails() throws Exception {
    KeysetHandle secretKeysetHandle = generateKeyset();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.serializeKeysetWithoutSecret(secretKeysetHandle));
  }

  @Test
  public void parseWithoutSecret_keysetWithSecretKeys_fails() throws Exception {
    KeysetHandle secretKeysetHandle = generateKeyset();
    byte[] serializedSecretKeyset =
        TinkProtoKeysetFormat.serializeKeyset(secretKeysetHandle, InsecureSecretKeyAccess.get());

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedSecretKeyset));
  }

  @Test
  public void parseWithoutSecretInvalidSerializedKeyset_fails() throws Exception {
    byte[] invalidSerializedKeyset = "invalid".getBytes(UTF_8);
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkProtoKeysetFormat.parseKeysetWithoutSecret(invalidSerializedKeyset));
  }

  @Test
  public void serializeKeyset_worksWithCleartextKeysetHandleReadAndBinaryKeysetReader()
      throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());

    KeysetHandle parseKeysetHandle =
        CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(serializedKeyset));

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void parseKeyset_worksWithCleartextKeysetHandleWriteAndBinaryKeysetWriter()
      throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(keysetHandle, BinaryKeysetWriter.withOutputStream(outputStream));
    byte[] serializedKeyset = outputStream.toByteArray();

    KeysetHandle parseKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void serializeKeysetWithoutSecret_worksWithKeysetHandleReadNoSecretAndBinaryKeysetReader()
      throws Exception {
    KeysetHandle publicKeysetHandle = generatePublicKeyset();

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeysetWithoutSecret(publicKeysetHandle);

    KeysetHandle parsePublicKeysetHandle =
        KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(serializedKeyset));

    assertKeysetHandleAreEqual(publicKeysetHandle, parsePublicKeysetHandle);
  }

  @Test
  public void parseKeysetWithoutSecret_worksWithKeysetHandleWriteNoSecretAndBinaryKeysetWriter()
      throws Exception {
    KeysetHandle publicKeysetHandle = generatePublicKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    publicKeysetHandle.writeNoSecret(BinaryKeysetWriter.withOutputStream(outputStream));
    byte[] serializedKeyset = outputStream.toByteArray();

    KeysetHandle parsePublicKeysetHandle =
        TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset);

    assertKeysetHandleAreEqual(publicKeysetHandle, parsePublicKeysetHandle);
  }

  @Test
  public void serializeEncrypted_worksWithKeysetHandleReadWithAssociatedDataAndBinaryKeysetReader()
      throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData);

    KeysetHandle parseKeysetHandle =
        KeysetHandle.readWithAssociatedData(
            BinaryKeysetReader.withBytes(serializedKeyset), keyEncryptionAead, associatedData);

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void parseEncrypted_worksWithKeysetHandleWriteWithAssociatedDataAndBinaryKeysetWriter()
      throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    keysetHandle.writeWithAssociatedData(
        BinaryKeysetWriter.withOutputStream(outputStream), keyEncryptionAead, associatedData);
    byte[] serializedKeyset = outputStream.toByteArray();

    KeysetHandle parseKeysetHandle =
        TinkProtoKeysetFormat.parseEncryptedKeyset(
            serializedKeyset, keyEncryptionAead, associatedData);

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void parseKeysetFromTestVector()
      throws Exception {
    // This was generated in Python using the BinaryKeysetWriter. It contains one HMAC key.
    byte[] serializedKeyset =
        Hex.decode(
            "0895e59bcc0612680a5c0a2e747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63"
                + "727970746f2e74696e6b2e486d61634b657912281a20cca20f02278003b3513f5d01759ac1302f7d"
                + "883f2f4a40025532ee1b11f9e587120410100803180110011895e59bcc062001");
    KeysetHandle handle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    Mac mac = handle.getPrimitive(Mac.class);
    mac.verifyMac(Hex.decode("016986f2956092d259136923c6f4323557714ec499"), "data".getBytes(UTF_8));
  }

  @Test
  public void parseEncryptedKeysetFromTestVector() throws Exception {
    // This is the same test vector as in KeysetHandleTest.
    // An AEAD key, with which we encrypted the mac keyset below.
    final byte[] serializedKeysetEncryptionKeyset =
        Hex.decode(
            "08b891f5a20412580a4c0a30747970652e676f6f676c65617069732e636f6d2f676f6f676c652e6372797"
                + "0746f2e74696e6b2e4165734561784b65791216120208101a10e5d7d0cdd649e81e7952260689b2"
                + "e1971801100118b891f5a2042001");
    KeysetHandle keysetEncryptionHandle = TinkProtoKeysetFormat.parseKeyset(
        serializedKeysetEncryptionKeyset, InsecureSecretKeyAccess.get());
    Aead keysetEncryptionAead = keysetEncryptionHandle.getPrimitive(Aead.class);

    // A keyset that contains one HMAC key, encrypted with the above, using associatedData
    final byte[] encryptedSerializedKeyset =
        Hex.decode(
            "12950101445d48b8b5f591efaf73a46df9ebd7b6ac471cc0cf4f815a4f012fcaffc8f0b2b10b30c33194f"
                + "0b291614bd8e1d2e80118e5d6226b6c41551e104ef8cd8ee20f1c14c1b87f6eed5fb04a91feafaa"
                + "cbf6f368519f36f97f7d08b24c8e71b5e620c4f69615ef0479391666e2fb32e46b416893fc4e564"
                + "ba927b22ebff2a77bd3b5b8d5afa162cbd35c94c155cdfa13c8a9c964cde21a4208f5909ce90112"
                + "3a0a2e747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f2e74696"
                + "e6b2e486d61634b6579100118f5909ce9012001");
    final byte[] associatedData = Hex.decode("abcdef330012");

    KeysetHandle handle =
        TinkProtoKeysetFormat.parseEncryptedKeyset(
            encryptedSerializedKeyset, keysetEncryptionAead, associatedData);

    Mac mac = handle.getPrimitive(Mac.class);
    final byte[] message = Hex.decode("");
    final byte[] tag = Hex.decode("011d270875989dd6fbd5f54dbc9520bb41efd058d5");
    mac.verifyMac(tag, message);
  }
}
