// Copyright 2023 Google LLC
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

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.signature.SignatureConfig;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class TinkLegacyKeysetFormatTest {

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    MacConfig.register();
    AeadConfig.register();
    SignatureConfig.register();
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
  public void parseKeysetWithoutSecret_works() throws Exception {
    KeysetHandle keysetHandle = generatePublicKeyset();
    byte[] serializedKeyset = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(keysetHandle);

    KeysetHandle parsedKeysetHandle =
        TinkLegacyKeysetFormat.parseKeysetWithoutSecret(
            BinaryKeysetReader.withBytes(serializedKeyset));

    assertTrue(keysetHandle.equalsKeyset(parsedKeysetHandle));
  }

  @Test
  public void parseKeysetWithoutSecret_throwsForKeysetWithPrivateKeys() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkLegacyKeysetFormat.parseKeysetWithoutSecret(
                BinaryKeysetReader.withBytes(serializedKeyset)));
  }

  @Test
  public void parseKeyset_works() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());

    KeysetHandle parsedKeysetHandle =
        TinkLegacyKeysetFormat.parseKeyset(
            BinaryKeysetReader.withBytes(serializedKeyset), InsecureSecretKeyAccess.get());

    assertTrue(keysetHandle.equalsKeyset(parsedKeysetHandle));
  }

  @Test
  public void parseKeyset_throwsNullPointerExceptionWithNull() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());

    assertThrows(
        NullPointerException.class,
        () ->
            TinkLegacyKeysetFormat.parseKeyset(
                BinaryKeysetReader.withBytes(serializedKeyset), null));
  }

  @Test
  public void parseEncryptedKeyset_works() throws Exception {
    Aead aead = generateAead();
    byte[] associatedData = new byte[] {1, 2, 3};

    KeysetHandle keysetHandle = generateKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(keysetHandle, aead, associatedData);

    KeysetHandle parsedKeysetHandle =
        TinkLegacyKeysetFormat.parseEncryptedKeyset(
            BinaryKeysetReader.withBytes(serializedKeyset), aead, associatedData);

    assertTrue(keysetHandle.equalsKeyset(parsedKeysetHandle));
  }

  @Test
  public void parseEncryptedKeyset_wrongAssociatedData_throws() throws Exception {
    Aead aead = generateAead();
    byte[] associatedData = new byte[] {1, 2, 3};

    KeysetHandle keysetHandle = generateKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(keysetHandle, aead, associatedData);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkLegacyKeysetFormat.parseEncryptedKeyset(
                BinaryKeysetReader.withBytes(serializedKeyset), aead, new byte[] {4, 5, 6}));
  }

  @Test
  public void serializeKeysetWithoutSecret_works() throws Exception {
    KeysetHandle keysetHandle = generatePublicKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    TinkLegacyKeysetFormat.serializeKeysetWithoutSecret(keysetHandle, writer);
    byte[] serializedKeyset = outputStream.toByteArray();

    KeysetHandle parsedKeyset = TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset);

    assertTrue(keysetHandle.equalsKeyset(parsedKeyset));
  }

  @Test
  public void serializeKeysetWithoutSecret_throwsForKeysetWithPrivateKeys() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkLegacyKeysetFormat.serializeKeysetWithoutSecret(keysetHandle, writer));
  }

  @Test
  public void serializeKeyset_works() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    TinkLegacyKeysetFormat.serializeKeyset(keysetHandle, writer, InsecureSecretKeyAccess.get());
    byte[] serializedKeyset = outputStream.toByteArray();

    KeysetHandle parsedKeyset =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    assertTrue(keysetHandle.equalsKeyset(parsedKeyset));
  }

  @Test
  public void serializeKeyset_throwsWithoutSecretKeyAccess() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    assertThrows(
        NullPointerException.class,
        () -> TinkLegacyKeysetFormat.serializeKeyset(keysetHandle, writer, null));
  }

  @Test
  public void serializeEncryptedKeyset_works() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();
    Aead aead = generateAead();
    byte[] associatedData = new byte[] {1, 2, 3};

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    TinkLegacyKeysetFormat.serializeEncryptedKeyset(keysetHandle, writer, aead, associatedData);
    byte[] serializedKeyset = outputStream.toByteArray();

    KeysetHandle parsedKeyset =
        TinkProtoKeysetFormat.parseEncryptedKeyset(serializedKeyset, aead, associatedData);
    assertTrue(keysetHandle.equalsKeyset(parsedKeyset));
  }

  @Test
  public void serializeEncryptedKeyset_throwsWithWrongAssociatedData() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();
    Aead aead = generateAead();
    byte[] associatedData = new byte[] {1, 2, 3};

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    TinkLegacyKeysetFormat.serializeEncryptedKeyset(keysetHandle, writer, aead, associatedData);
    byte[] serializedKeyset = outputStream.toByteArray();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset, aead, new byte[] {4, 5, 6}));
  }
}
