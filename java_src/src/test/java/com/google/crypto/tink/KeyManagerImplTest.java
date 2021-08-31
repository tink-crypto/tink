// Copyright 2020 Google LLC
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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests the methods implemented in KeyManagerImpl using the concrete implementation above. */
@RunWith(JUnit4.class)
public final class KeyManagerImplTest {
  /** Implementation of a KeyTypeManager for testing. */
  private static class TestKeyTypeManager extends KeyTypeManager<AesGcmKey> {
    public TestKeyTypeManager() {
      super(
          AesGcmKey.class,
          new PrimitiveFactory<Aead, AesGcmKey>(Aead.class) {
            @Override
            public Aead getPrimitive(AesGcmKey key) throws GeneralSecurityException {
              return new AesGcmJce(key.getKeyValue().toByteArray());
            }
          },
          new PrimitiveFactory<FakeAead, AesGcmKey>(FakeAead.class) {
            @Override
            public FakeAead getPrimitive(AesGcmKey key) {
              return new FakeAead();
            }
          });
    }

    @Override
    public String getKeyType() {
      return "type.googleapis.com/google.crypto.tink.AesGcmKey";
    }

    @Override
    public int getVersion() {
      return 1;
    }

    @Override
    public KeyMaterialType keyMaterialType() {
      return KeyMaterialType.SYMMETRIC;
    }

    @Override
    public void validateKey(AesGcmKey keyProto) throws GeneralSecurityException {
      // Throw by hand so we can verify the exception comes from here.
      if (keyProto.getKeyValue().size() != 16) {
        throw new GeneralSecurityException("validateKey(AesGcmKey) failed");
      }
    }

    @Override
    public AesGcmKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      return AesGcmKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    }

    @Override
    public KeyFactory<AesGcmKeyFormat, AesGcmKey> keyFactory() {
      return new KeyFactory<AesGcmKeyFormat, AesGcmKey>(AesGcmKeyFormat.class) {
        @Override
        public void validateKeyFormat(AesGcmKeyFormat format) throws GeneralSecurityException {
          // Throw by hand so we can verify the exception comes from here.
          if (format.getKeySize() != 16) {
            throw new GeneralSecurityException("validateKeyFormat(AesGcmKeyFormat) failed");
          }
        }

        @Override
        public AesGcmKeyFormat parseKeyFormat(ByteString byteString)
            throws InvalidProtocolBufferException {
          return AesGcmKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
        }

        @Override
        public AesGcmKey createKey(AesGcmKeyFormat format) throws GeneralSecurityException {
          return AesGcmKey.newBuilder()
              .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
              .setVersion(getVersion())
              .build();
        }
      };
    }
  }

  @Test
  public void getPrimitive_byteString_works() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    MessageLite key = keyManager.newKey(AesGcmKeyFormat.newBuilder().setKeySize(16).build());
    keyManager.getPrimitive(key.toByteString());
  }

  @Test
  public void getPrimitive_fakeAead_byteString_works() throws Exception {
    KeyManager<FakeAead> fakeAeadKeyManager =
        new KeyManagerImpl<>(new TestKeyTypeManager(), FakeAead.class);
    MessageLite key =
        fakeAeadKeyManager.newKey(AesGcmKeyFormat.newBuilder().setKeySize(16).build());
    fakeAeadKeyManager.getPrimitive(key.toByteString());
  }

  @Test
  public void creatingKeyManager_nonSupportedPrimitive_fails() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new KeyManagerImpl<>(new TestKeyTypeManager(), Integer.class));
  }

  @Test
  public void getPrimitive_byteString_throwsInvalidKey() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    MessageLite notAKey = AesGcmKey.getDefaultInstance();
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> keyManager.getPrimitive(notAKey.toByteString()));
    assertThat(e.toString()).contains("validateKey(AesGcmKey) failed");
  }

  @Test
  public void getPrimitive_messageLite_works() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    MessageLite key = keyManager.newKey(AesGcmKeyFormat.newBuilder().setKeySize(16).build());
    keyManager.getPrimitive(key);
  }

  @Test
  public void getPrimitive_messageLite_throwsIfVoid() throws Exception {
    KeyManager<Void> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Void.class);
    MessageLite key = keyManager.newKey(AesGcmKeyFormat.newBuilder().setKeySize(16).build());
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> keyManager.getPrimitive(key));
    assertThat(e.toString()).contains("Void");
  }

  @Test
  public void getPrimitive_messageLite_throwsWrongProto() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    MessageLite notAKey = AesGcmKeyFormat.getDefaultInstance();
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> keyManager.getPrimitive(notAKey));
    assertThat(e.toString()).contains("Expected proto of type");
  }

  @Test
  public void getPrimitive_messageLite_throwsInvalidKey() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    MessageLite notAKey = AesGcmKey.getDefaultInstance();
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> keyManager.getPrimitive(notAKey));
    assertThat(e.toString()).contains("validateKey(AesGcmKey) failed");
  }

  @Test
  public void newKey_byteString_works() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    keyManager.newKey(AesGcmKeyFormat.newBuilder().setKeySize(16).build().toByteString());
  }

  @Test
  public void newKey_byteString_throwsInvalidKeySize() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                keyManager.newKey(
                    AesGcmKeyFormat.newBuilder().setKeySize(17).build().toByteString()));
    assertThat(e.toString()).contains("validateKeyFormat(AesGcmKeyFormat) failed");
  }

  @Test
  public void newKey_messageLite_works() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    keyManager.newKey(AesGcmKeyFormat.newBuilder().setKeySize(16).build());
  }

  @Test
  public void newKey_messageLite_throwsWrongProto() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> keyManager.newKey(AesGcmKey.getDefaultInstance()));
    assertThat(e.toString()).contains("Expected proto of type");
  }

  @Test
  public void newKey_messageLite_throwsInvalidKeySize() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> keyManager.newKey((MessageLite) AesGcmKeyFormat.getDefaultInstance()));
    assertThat(e.toString()).contains("validateKeyFormat(AesGcmKeyFormat) failed");
  }

  @Test
  public void doesSupport_returnsTrue() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    assertThat(keyManager.doesSupport("type.googleapis.com/google.crypto.tink.AesGcmKey")).isTrue();
  }

  @Test
  public void doesSupport_returnsFalse() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    assertThat(keyManager.doesSupport("type.googleapis.com/SomeOtherKey")).isFalse();
  }

  @Test
  public void getKeyType() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    assertThat(keyManager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.AesGcmKey");
  }

  @Test
  public void newKeyData_works() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    keyManager.newKeyData(AesGcmKeyFormat.newBuilder().setKeySize(16).build().toByteString());
  }

  @Test
  public void newKeyData_typeUrlCorrect() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    assertThat(
            keyManager
                .newKeyData(AesGcmKeyFormat.newBuilder().setKeySize(16).build().toByteString())
                .getTypeUrl())
        .isEqualTo("type.googleapis.com/google.crypto.tink.AesGcmKey");
  }

  @Test
  public void newKeyData_valueLengthCorrect() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    // We allow the keysize to be bigger than 16 since proto serialized adds some overhead.
    assertThat(
            keyManager
                .newKeyData(AesGcmKeyFormat.newBuilder().setKeySize(16).build().toByteString())
                .getValue()
                .size())
        .isAtLeast(16);
  }

  @Test
  public void newKeyData_wrongKeySize_throws() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    // We allow the keysize to be bigger than 16 since proto serialized adds some overhead.
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                keyManager.newKeyData(
                    AesGcmKeyFormat.newBuilder().setKeySize(17).build().toByteString()));
    assertThat(e.toString()).contains("validateKeyFormat(AesGcmKeyFormat) failed");
  }

  @Test
  public void newKeyData_keyMaterialTypeCorrect() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    assertThat(
            keyManager
                .newKeyData(AesGcmKeyFormat.newBuilder().setKeySize(16).build().toByteString())
                .getKeyMaterialType())
        .isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void getPrimitiveClass() throws Exception {
    KeyManager<Aead> keyManager = new KeyManagerImpl<>(new TestKeyTypeManager(), Aead.class);
    assertThat(keyManager.getPrimitiveClass()).isEqualTo(Aead.class);
  }

  /** Implementation of a KeyTypeManager for testing, not supporting creating new keys. */
  private static class TestKeyTypeManagerWithoutKeyFactory extends KeyTypeManager<AesGcmKey> {
    public TestKeyTypeManagerWithoutKeyFactory() {
      super(AesGcmKey.class);
    }

    @Override
    public String getKeyType() {
      return "type.googleapis.com/google.crypto.tink.AesGcmKey";
    }

    @Override
    public int getVersion() {
      return 1;
    }

    @Override
    public KeyMaterialType keyMaterialType() {
      return KeyMaterialType.SYMMETRIC;
    }

    @Override
    public void validateKey(AesGcmKey keyProto) {}

    @Override
    public AesGcmKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      return AesGcmKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    }
  }

  @Test
  public void newKey_byteString_throwsUnsupportedOperation() throws Exception {
    KeyManager<Void> keyManager =
        new KeyManagerImpl<>(new TestKeyTypeManagerWithoutKeyFactory(), Void.class);
    assertThrows(
        UnsupportedOperationException.class, () -> keyManager.newKey(ByteString.copyFromUtf8("")));
  }

  @Test
  public void newKey_messageList_throwsUnsupportedOperation() throws Exception {
    KeyManager<Void> keyManager =
        new KeyManagerImpl<>(new TestKeyTypeManagerWithoutKeyFactory(), Void.class);
    assertThrows(
        UnsupportedOperationException.class,
        () -> keyManager.newKey(AesGcmKey.getDefaultInstance()));
  }

  @Test
  public void newKeyData_byteString_throwsUnsupportedOperation() throws Exception {
    KeyManager<Void> keyManager =
        new KeyManagerImpl<>(new TestKeyTypeManagerWithoutKeyFactory(), Void.class);
    assertThrows(
        UnsupportedOperationException.class,
        () -> keyManager.newKeyData(ByteString.copyFromUtf8("")));
  }

  private static class FakeAead {}
}
