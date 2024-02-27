// Copyright 2024 Google LLC
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

package com.google.crypto.tink.aead.internal;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Hex;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class LegacyFullAeadIntegrationTest {
  private static final String TYPE_URL = "type.googleapis.com/custom.AesCtrHmacAeadKey";

  private static KeysetHandle rawKeysetHandle;
  private static KeysetHandle tinkKeysetHandle;
  private static KeysetHandle crunchyKeysetHandle;
  private static KeysetHandle legacyKeysetHandle;

  @BeforeClass
  public static void setUp() throws Exception {
    AeadConfig.register();
    LegacyAesCtrHmacTestKeyManager.register();

    AesCtrKey aesCtrKey =
        AesCtrKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Hex.decode("abcdefabcdefabcdefabcdefabcdefab")))
            .setParams(AesCtrParams.newBuilder().setIvSize(16).build())
            .build();
    HmacKey hmacKey =
        HmacKey.newBuilder()
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(32))
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")))
            .build();
    AesCtrHmacAeadKey protoKey = AesCtrHmacAeadKey.newBuilder().setAesCtrKey(aesCtrKey)
        .setHmacKey(hmacKey).build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(protoKey.toByteString())
            .build();

    Keyset.Key rawKeysetKey =
        Keyset.Key.newBuilder()
            .setKeyData(keyData)
            .setStatus(KeyStatusType.ENABLED)
            .setKeyId(0x0000002a)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    rawKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(
            Keyset.newBuilder()
                .addKey(rawKeysetKey)
                .setPrimaryKeyId(0x0000002a)
                .build()
                .toByteArray(),
            InsecureSecretKeyAccess.get());

    Keyset.Key tinkKeysetKey =
        Keyset.Key.newBuilder()
            .setKeyData(keyData)
            .setStatus(KeyStatusType.ENABLED)
            .setKeyId(0x0000002a)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    tinkKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(
            Keyset.newBuilder()
                .addKey(tinkKeysetKey)
                .setPrimaryKeyId(0x0000002a)
                .build()
                .toByteArray(),
            InsecureSecretKeyAccess.get());

    Keyset.Key crunchyKeysetKey =
        Keyset.Key.newBuilder()
            .setKeyData(keyData)
            .setStatus(KeyStatusType.ENABLED)
            .setKeyId(0x0000002a)
            .setOutputPrefixType(OutputPrefixType.CRUNCHY)
            .build();
    crunchyKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(
            Keyset.newBuilder()
                .addKey(crunchyKeysetKey)
                .setPrimaryKeyId(0x0000002a)
                .build()
                .toByteArray(),
            InsecureSecretKeyAccess.get());

    Keyset.Key legacyKeysetKey =
        Keyset.Key.newBuilder()
            .setKeyData(keyData)
            .setStatus(KeyStatusType.ENABLED)
            .setKeyId(0x0000002a)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    legacyKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(
            Keyset.newBuilder()
                .addKey(legacyKeysetKey)
                .setPrimaryKeyId(0x0000002a)
                .build()
                .toByteArray(),
            InsecureSecretKeyAccess.get());
  }

  @Test
  public void generateNew_works() throws Exception {
    KeyTemplate template = LegacyAesCtrHmacTestKeyManager.templateWithTinkPrefix();
    KeysetHandle handle =
        KeysetHandle.generateNew(TinkProtoParametersFormat.parse(template.toByteArray()));
    Aead aead = handle.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);

    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
    assertThrows(
        GeneralSecurityException.class, () -> aead.decrypt(ciphertext, "invalid".getBytes(UTF_8)));
    assertThrows(
        GeneralSecurityException.class,
        () -> aead.decrypt("invalid".getBytes(UTF_8), associatedData));
  }

  @Test
  public void endToEnd_works() throws Exception {
    Aead aead = tinkKeysetHandle.getPrimitive(Aead.class);

    assertThat(aead).isNotNull();
  }

  @Test
  public void endToEnd_decryptIsCorrect() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] ciphertext =
        Hex.decode(
            "3ece3dbf46993de86f0f68730c3f577b"
                + "e7c7ff4deb4e2f3a33db5996c017b312"
                + "ddc54c64ce990e05b3898b96d8d1a8e0"
                + "5a44031302c81f3c9e");
    byte[] plaintext = "plaintext".getBytes(UTF_8);

    Aead aead = rawKeysetHandle.getPrimitive(Aead.class);

    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void endToEnd_encryptDecryptWorks() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] plaintext = "plaintext".getBytes(UTF_8);

    Aead aead = rawKeysetHandle.getPrimitive(Aead.class);

    assertThat(aead.decrypt(aead.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
  }

  @Test
  public void endToEnd_wrongCiphertextThrows() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] badCiphertext =
        Hex.decode(
            "badbadbadbadbadbadbadbadbadbadba"
                + "badbadbadbadbadbadbadbadbadbadba"
                + "badbadbadbadbadbadbadbadbadbadba"
                + "badbadbadbadbadbad");

    Aead aead = rawKeysetHandle.getPrimitive(Aead.class);

    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(badCiphertext, associatedData));
  }

  @Test
  public void endToEnd_wrongAssociatedDataThrows() throws Exception {
    byte[] badAssociatedData = Hex.decode("badbadbadbadbadb");
    byte[] ciphertext =
        Hex.decode(
            "3ece3dbf46993de86f0f68730c3f577b"
                + "e7c7ff4deb4e2f3a33db5996c017b312"
                + "ddc54c64ce990e05b3898b96d8d1a8e0"
                + "5a44031302c81f3c9e");

    Aead aead = rawKeysetHandle.getPrimitive(Aead.class);

    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, badAssociatedData));
  }

  // The following tests ensure that ciphertext prefixes are handled correctly. I.e.:
  // - `encrypt()` adds the expected prefix to the produced ciphertext
  // - `decrypt()` accepts the correct ciphertext prefixes
  // - `decrypt()` refuses incorrect ciphertext prefixes
  @Test
  public void endToEnd_encryptAddsTinkPrefixCorrectly() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] plaintext = "plaintext".getBytes(UTF_8);

    Aead aead = tinkKeysetHandle.getPrimitive(Aead.class);

    assertThat(
            Hex.encode(
                Arrays.copyOfRange(
                    aead.encrypt(plaintext, associatedData), 0, CryptoFormat.TINK_PREFIX_SIZE)))
        .isEqualTo("010000002a");
  }

  @Test
  public void endToEnd_encryptAddsCrunchyPrefixCorrectly() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] plaintext = "plaintext".getBytes(UTF_8);

    Aead aead = crunchyKeysetHandle.getPrimitive(Aead.class);

    assertThat(
        Hex.encode(
            Arrays.copyOfRange(
                aead.encrypt(plaintext, associatedData), 0, CryptoFormat.NON_RAW_PREFIX_SIZE)))
        .isEqualTo("000000002a");
  }

  @Test
  public void endToEnd_encryptAddsLegacyPrefixCorrectly() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] plaintext = "plaintext".getBytes(UTF_8);

    Aead aead = legacyKeysetHandle.getPrimitive(Aead.class);

    assertThat(
        Hex.encode(
            Arrays.copyOfRange(
                aead.encrypt(plaintext, associatedData), 0, CryptoFormat.NON_RAW_PREFIX_SIZE)))
        .isEqualTo("000000002a");
  }

  @Test
  public void endToEnd_decryptAcceptsCorrectTinkPrefix() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] ciphertext =
        Hex.decode(
            "010000002a3ece3dbf46993de86f0f68"
                + "730c3f577be7c7ff4deb4e2f3a33db59"
                + "96c017b312ddc54c64ce990e05b3898b"
                + "96d8d1a8e05a44031302c81f3c9e");
    byte[] plaintext = "plaintext".getBytes(UTF_8);

    Aead aead = tinkKeysetHandle.getPrimitive(Aead.class);

    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void endToEnd_decryptAcceptsCorrectCrunchyPrefix() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] ciphertext =
        Hex.decode(
            "000000002a3ece3dbf46993de86f0f68"
                + "730c3f577be7c7ff4deb4e2f3a33db59"
                + "96c017b312ddc54c64ce990e05b3898b"
                + "96d8d1a8e05a44031302c81f3c9e");
    byte[] plaintext = "plaintext".getBytes(UTF_8);

    Aead aead = crunchyKeysetHandle.getPrimitive(Aead.class);

    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void endToEnd_decryptAcceptsCorrectLegacyPrefix() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] ciphertext =
        Hex.decode(
            "000000002a3ece3dbf46993de86f0f68"
                + "730c3f577be7c7ff4deb4e2f3a33db59"
                + "96c017b312ddc54c64ce990e05b3898b"
                + "96d8d1a8e05a44031302c81f3c9e");
    byte[] plaintext = "plaintext".getBytes(UTF_8);

    Aead aead = legacyKeysetHandle.getPrimitive(Aead.class);

    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void endToEnd_decryptWrongTinkPrefixThrows() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] ciphertextBadPrefix =
        Hex.decode(
            "badbadbadb3ece3dbf46993de86f0f68"
                + "730c3f577be7c7ff4deb4e2f3a33db59"
                + "96c017b312ddc54c64ce990e05b3898b"
                + "96d8d1a8e05a44031302c81f3c9e");

    Aead aead = tinkKeysetHandle.getPrimitive(Aead.class);

    assertThrows(
        GeneralSecurityException.class, () -> aead.decrypt(ciphertextBadPrefix, associatedData));
  }

  @Test
  public void endToEnd_decryptWrongCrunchyPrefixThrows() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] ciphertextBadPrefix =
        Hex.decode(
            "badbadbadb3ece3dbf46993de86f0f68"
                + "730c3f577be7c7ff4deb4e2f3a33db59"
                + "96c017b312ddc54c64ce990e05b3898b"
                + "96d8d1a8e05a44031302c81f3c9e");

    Aead aead = crunchyKeysetHandle.getPrimitive(Aead.class);

    assertThrows(
        GeneralSecurityException.class, () -> aead.decrypt(ciphertextBadPrefix, associatedData));
  }

  @Test
  public void endToEnd_decryptWrongLegacyPrefixThrows() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] ciphertextBadPrefix =
        Hex.decode(
            "badbadbadb3ece3dbf46993de86f0f68"
                + "730c3f577be7c7ff4deb4e2f3a33db59"
                + "96c017b312ddc54c64ce990e05b3898b"
                + "96d8d1a8e05a44031302c81f3c9e");

    Aead aead = legacyKeysetHandle.getPrimitive(Aead.class);

    assertThrows(
        GeneralSecurityException.class, () -> aead.decrypt(ciphertextBadPrefix, associatedData));
  }
}
