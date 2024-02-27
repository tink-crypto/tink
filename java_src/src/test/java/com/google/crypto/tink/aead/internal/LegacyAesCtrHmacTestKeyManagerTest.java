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

package com.google.crypto.tink.aead.internal;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.aead.AeadWrapper;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.Hex;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class LegacyAesCtrHmacTestKeyManagerTest {

  private static final String TYPE_URL = "type.googleapis.com/custom.AesCtrHmacAeadKey";

  @BeforeClass
  public static void setUp() throws Exception {
    AeadWrapper.register();
    LegacyAesCtrHmacTestKeyManager.register();
  }

  @DataPoints("templates")
  public static final KeyTemplate[] TEMPLATES =
      new KeyTemplate[] {
        LegacyAesCtrHmacTestKeyManager.templateWithTinkPrefix(),
        LegacyAesCtrHmacTestKeyManager.templateWithoutPrefix()
      };

  @Theory
  public void generateNewWithTemplateWithTinkPrefix_works(
      @FromDataPoints("templates") KeyTemplate template) throws Exception {
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

  @Theory
  public void withPrefixAddsPrefix() throws Exception {
    KeysetHandle handleWithPrefix =
        KeysetHandle.generateNew(
            TinkProtoParametersFormat.parse(
                LegacyAesCtrHmacTestKeyManager.templateWithTinkPrefix().toByteArray()));
    KeysetHandle handleWithoutPrefix =
        KeysetHandle.generateNew(
            TinkProtoParametersFormat.parse(
                LegacyAesCtrHmacTestKeyManager.templateWithoutPrefix().toByteArray()));
    Aead aeadWithPrefix = handleWithPrefix.getPrimitive(Aead.class);
    Aead aeadWithoutPrefix = handleWithoutPrefix.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    byte[] ciphertextWithPrefix = aeadWithPrefix.encrypt(plaintext, associatedData);
    byte[] ciphertextWithoutPrefix = aeadWithoutPrefix.encrypt(plaintext, associatedData);

    // The output prefix is 5 bytes, so the length difference of the two ciphertexts must be 5.
    assertThat(ciphertextWithPrefix.length - ciphertextWithoutPrefix.length).isEqualTo(5);
  }

  @Theory
  public void getPrimitive_works() throws Exception {
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
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.newBuilder().setAesCtrKey(aesCtrKey).setHmacKey(hmacKey).build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();

    Aead aead = Registry.getPrimitive(keyData, Aead.class);

    assertThat(aead).isNotNull();
    assertThat(aead).isInstanceOf(EncryptThenAuthenticate.class);
  }

  @Theory
  public void getPrimitive_withInvalidKey_fails() throws Exception {
    AesCtrKey aesCtrKey =
        AesCtrKey.newBuilder()
            .setVersion(1) // Version 1 is not valid.
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
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.newBuilder().setAesCtrKey(aesCtrKey).setHmacKey(hmacKey).build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();

    assertThrows(GeneralSecurityException.class, () -> Registry.getPrimitive(keyData, Aead.class));
  }

  @Theory
  public void getPrimitive_encryptDecrypt_works() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] aad = "aad".getBytes(UTF_8);
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
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.newBuilder().setAesCtrKey(aesCtrKey).setHmacKey(hmacKey).build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();

    Aead aead = Registry.getPrimitive(keyData, Aead.class);

    assertThat(aead.decrypt(aead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
  }
}
