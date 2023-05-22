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

package com.google.crypto.tink.custom;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.ChaCha20Poly1305Parameters;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import com.google.protobuf.BytesValue;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import com.google.protobuf.StringValue;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** This test creates a custom Aead KeyManager and uses it. */
@RunWith(JUnit4.class)
public final class CustomAeadKeyManagerTest {

  /**
   * A custom implementation of {@link com.google.crypto.tink.KeyManager} for AES GCM 128.
   *
   * <p>It only implements the methods of the KeyManager interface that are needed.
   */
  static class MyCustomKeyManager implements KeyManager<Aead> {

    private static final String TYPE_URL =
        "type.googleapis.com/google.crypto.tink.testonly.CustomAeadKey";

    private static final String AEAD_AES_128_GCM = "AEAD_AES_128_GCM";

    @Override
    public Aead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
      try {
        BytesValue key =
            BytesValue.parseFrom(serializedKey, ExtensionRegistryLite.getEmptyRegistry());
        byte[] keyValue = key.getValue().toByteArray();
        if (keyValue.length != 16) {
          throw new GeneralSecurityException("unexpected length of keyValue");
        }
        return new AesGcmJce(keyValue);
      } catch (InvalidProtocolBufferException e) {
        throw new GeneralSecurityException(e);
      }
    }

    @Override
    public Aead getPrimitive(MessageLite key) throws GeneralSecurityException {
      throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
      throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
      throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public boolean doesSupport(String typeUrl) {
      throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public String getKeyType() {
      return TYPE_URL;
    }

    @Override
    public int getVersion() {
      throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public Class<Aead> getPrimitiveClass() {
      return Aead.class;
    }

    @Override
    public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
      // serializedKeyFormat is a StringValue proto. The only allowed string is "AEAD_AES_128_GCM".
      try {
        StringValue keyFormat =
            StringValue.parseFrom(serializedKeyFormat, ExtensionRegistryLite.getEmptyRegistry());
        if (!keyFormat.getValue().equals(AEAD_AES_128_GCM)) {
          throw new GeneralSecurityException("unknown algorithm");
        }
        byte[] rawAesKey = Random.randBytes(16);
        BytesValue value = BytesValue.of(ByteString.copyFrom(rawAesKey));
        return KeyData.newBuilder()
            .setTypeUrl(getKeyType())
            .setValue(value.toByteString())
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .build();
      } catch (InvalidProtocolBufferException e) {
        throw new GeneralSecurityException(e);
      }
    }

    static Parameters aesGcm128Parameters() throws GeneralSecurityException {
      StringValue format = StringValue.of(AEAD_AES_128_GCM);
      KeyTemplate template =
          KeyTemplate.newBuilder()
              .setValue(format.toByteString())
              .setTypeUrl(TYPE_URL)
              .setOutputPrefixType(OutputPrefixType.RAW)
              .build();
      return TinkProtoParametersFormat.parse(template.toByteArray());
    }

    static KeysetHandle aesGcm128KeyToKeysetHandle(
        byte[] rawAesKey, int keyId, OutputPrefixType outputPrefixType)
        throws GeneralSecurityException {
      if (rawAesKey.length != 16) {
        throw new IllegalArgumentException("unexpected raw key length");
      }
      BytesValue value = BytesValue.of(ByteString.copyFrom(rawAesKey));
      Keyset keyset =
          Keyset.newBuilder()
              .addKey(
                  Keyset.Key.newBuilder()
                      .setStatus(KeyStatusType.ENABLED)
                      .setOutputPrefixType(outputPrefixType)
                      .setKeyId(keyId)
                      .setKeyData(
                          KeyData.newBuilder()
                              .setTypeUrl(TYPE_URL)
                              .setValue(value.toByteString())
                              .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
                              .build())
                      .build())
              .setPrimaryKeyId(keyId)
              .build();
      return CleartextKeysetHandle.fromKeyset(keyset);
    }
  }

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();
    Registry.registerKeyManager(new MyCustomKeyManager(), /* newKeyAllowed= */ true);
  }

  @Test
  public void createEncryptAndDecrypt_success() throws Exception {
    Parameters aesGcm128Parameters = MyCustomKeyManager.aesGcm128Parameters();
    KeysetHandle handle = KeysetHandle.generateNew(aesGcm128Parameters);
    Aead aead = handle.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void importExistingKey_decrypts() throws Exception {
    byte[] rawAesKey = Random.randBytes(16);
    Aead jceAead = new AesGcmJce(rawAesKey);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = jceAead.encrypt(plaintext, associatedData);

    KeysetHandle handle =
        MyCustomKeyManager.aesGcm128KeyToKeysetHandle(
            rawAesKey, /* keyId= */ 0x11223344, OutputPrefixType.RAW);
    Aead aead = handle.getPrimitive(Aead.class);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void encryptAndDecryptWithTinkPrefix_success() throws Exception {
    // Create a new key and import it with output prefix type TINK with a fixed key ID.
    byte[] rawAesKey = Random.randBytes(16);
    int keyId = 0x11223344;
    KeysetHandle handle =
        MyCustomKeyManager.aesGcm128KeyToKeysetHandle(rawAesKey, keyId, OutputPrefixType.TINK);

    Aead aead = handle.getPrimitive(Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);

    // Check that ciphertext generated using OutputPrefixType.TINK has a 5 byte prefix:
    // the first byte is always 0x01, and the next 4 bytes are the big-endian encoded key ID.
    byte[] prefix = Arrays.copyOf(ciphertext, 5);
    assertThat(prefix)
        .isEqualTo(new byte[] {(byte) 0x01, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44});

    // Check that AesGcmJce can decrypt using the raw key, if the prefix is removed.
    byte[] ciphertextWithoutPrefix = Arrays.copyOfRange(ciphertext, 5, ciphertext.length);
    Aead jceAead = new AesGcmJce(rawAesKey);
    assertThat(jceAead.decrypt(ciphertextWithoutPrefix, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void keysetWithCustomAndTinkKeys_decrypts() throws Exception {
    byte[] rawAesKey = Random.randBytes(16);
    Aead jceAead = new AesGcmJce(rawAesKey);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = jceAead.encrypt(plaintext, associatedData);

    // Create keyset handle with normal Tink key
    KeysetHandle handleWithTinkKey =
        KeysetHandle.generateNew(
            ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.TINK));
    Aead aead2 = handleWithTinkKey.getPrimitive(Aead.class);
    byte[] ciphertext2 = aead2.encrypt(plaintext, associatedData);

    KeysetHandle handle =
        MyCustomKeyManager.aesGcm128KeyToKeysetHandle(
            rawAesKey, /* keyId= */ 0x11223344, OutputPrefixType.RAW);
    // Create keyset handle with both the custom key and the normal Tink key
    KeysetHandle handle2 =
        KeysetHandle.newBuilder(handle)
            .addEntry(KeysetHandle.importKey(handleWithTinkKey.getAt(0).getKey()).makePrimary())
            .build();

    // Decrypt both ciphertexts
    Aead aead = handle2.getPrimitive(Aead.class);
    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
    assertThat(aead.decrypt(ciphertext2, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void serializeAndParse_decrypts() throws Exception {
    Parameters aesGcm128Parameters = MyCustomKeyManager.aesGcm128Parameters();
    KeysetHandle handle = KeysetHandle.generateNew(aesGcm128Parameters);
    Aead aead = handle.getPrimitive(Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());

    KeysetHandle handle2 =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    Aead aead2 = handle2.getPrimitive(Aead.class);
    byte[] decrypted = aead2.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }
}
