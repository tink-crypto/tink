// Copyright 2018 Google Inc.
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
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil.DummyAead;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests the methods implemented in KeyManagerBase using the concrete implementation above. */
@RunWith(JUnit4.class)
public final class KeyManagerBaseTest {
  /** Keymanager for testing. Only produces dummy aeads, and wants the key size to be exactly 16. */
  static class TestKeyManager extends KeyManagerBase<Aead, AesGcmKey, AesGcmKeyFormat> {
    public TestKeyManager() {
      super(Aead.class, AesGcmKey.class, AesGcmKeyFormat.class, TYPE_URL);
    }

    private static final int VERSION = 0;

    public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesGcmKey";

    @Override
    protected Aead getPrimitiveFromKey(AesGcmKey key) throws GeneralSecurityException {
      return new DummyAead();
    }

    @Override
    protected AesGcmKey newKeyFromFormat(AesGcmKeyFormat format) throws GeneralSecurityException {
      return AesGcmKey.newBuilder()
          .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
          .setVersion(VERSION)
          .build();
    }

    @Override
    public int getVersion() {
      return VERSION;
    }

    @Override
    protected KeyMaterialType keyMaterialType() {
      return KeyMaterialType.SYMMETRIC;
    }

    @Override
    protected AesGcmKey parseKeyProto(ByteString byteString) throws InvalidProtocolBufferException {
      return AesGcmKey.parseFrom(byteString);
    }

    @Override
    protected AesGcmKeyFormat parseKeyFormatProto(ByteString byteString)
        throws InvalidProtocolBufferException {
      return AesGcmKeyFormat.parseFrom(byteString);
    }

    private void throwIfNot16(int size) throws GeneralSecurityException {
      if (size != 16) {
        throw new InvalidAlgorithmParameterException("invalid key size; only size 16 is good.");
      }
    }

    @Override
    protected void validateKey(AesGcmKey key) throws GeneralSecurityException {
      Validators.validateVersion(key.getVersion(), VERSION);
      throwIfNot16(key.getKeyValue().size());
    }

    @Override
    protected void validateKeyFormat(AesGcmKeyFormat format) throws GeneralSecurityException {
      throwIfNot16(format.getKeySize());
    }
  }

  @Test
  public void getPrimitive_ByteString_works() throws Exception {
    TestKeyManager keyManager = new TestKeyManager();
    MessageLite key = keyManager.newKey(AesGcmKeyFormat.newBuilder().setKeySize(16).build());
    keyManager.getPrimitive(key.toByteString());
  }

  @Test
  public void getPrimitive_ByteString_throwsInvalidKey() throws Exception {
    TestKeyManager keyManager = new TestKeyManager();
    MessageLite notAKey = AesGcmKey.getDefaultInstance();
    try {
      keyManager.getPrimitive(notAKey.toByteString());
      fail("expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("invalid key size");
    }
  }

  @Test
  public void getPrimitive_MessageLite_works() throws Exception {
    TestKeyManager keyManager = new TestKeyManager();
    MessageLite key = keyManager.newKey(AesGcmKeyFormat.newBuilder().setKeySize(16).build());
    keyManager.getPrimitive(key);
  }

  @Test
  public void getPrimitive_MessageLite_throwsWrongProto() throws Exception {
    TestKeyManager keyManager = new TestKeyManager();
    MessageLite notAKey = AesGcmKeyFormat.getDefaultInstance();
    try {
      keyManager.getPrimitive(notAKey);
      fail("expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("Expected proto of type");
    }
  }

  @Test
  public void getPrimitive_MessageLite_throwsInvalidKey() throws Exception {
    TestKeyManager keyManager = new TestKeyManager();
    MessageLite notAKey = AesGcmKey.getDefaultInstance();
    try {
      keyManager.getPrimitive(notAKey);
      fail("expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("invalid key size");
    }
  }

  @Test
  public void newKey_ByteString_works() throws Exception {
    TestKeyManager keyManager = new TestKeyManager();
    keyManager.newKey(AesGcmKeyFormat.newBuilder().setKeySize(16).build().toByteString());
  }

  @Test
  public void newKey_ByteString_throwsInvalidKeySize() throws Exception {
    TestKeyManager keyManager = new TestKeyManager();
    try {
      keyManager.newKey(AesGcmKeyFormat.newBuilder().setKeySize(17).build().toByteString());
      fail("expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("invalid key size");
    }
  }

  @Test
  public void newKey_MessageLite_works() throws Exception {
    TestKeyManager keyManager = new TestKeyManager();
    keyManager.newKey(AesGcmKeyFormat.newBuilder().setKeySize(16).build());
  }

  @Test
  public void newKey_MessageLite_throwsWrongProto() throws Exception {
    TestKeyManager keyManager = new TestKeyManager();
    try {
      keyManager.newKey(AesGcmKey.getDefaultInstance());
      fail("expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("Expected proto of type");
    }
  }

  @Test
  public void doesSupport_returnsTrue() throws Exception {
    assertThat(new TestKeyManager().doesSupport("type.googleapis.com/google.crypto.tink.AesGcmKey"))
        .isTrue();
  }

  @Test
  public void doesSupport_returnsFalse() throws Exception {
    assertThat(new TestKeyManager().doesSupport("type.googleapis.com/SomeOtherKey")).isFalse();
  }

  @Test
  public void getKeyType() throws Exception {
    assertThat(new TestKeyManager().getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.AesGcmKey");
  }

  @Test
  public void newKeyData_works() throws Exception {
    TestKeyManager keyManager = new TestKeyManager();
    keyManager.newKeyData(AesGcmKeyFormat.newBuilder().setKeySize(16).build().toByteString());
  }

  @Test
  public void newKeyData_typeUrlCorrect() throws Exception {
    TestKeyManager keyManager = new TestKeyManager();
    assertThat(
            keyManager
                .newKeyData(AesGcmKeyFormat.newBuilder().setKeySize(16).build().toByteString())
                .getTypeUrl())
        .isEqualTo("type.googleapis.com/google.crypto.tink.AesGcmKey");
  }

  @Test
  public void newKeyData_valueLengthCorrect() throws Exception {
    TestKeyManager keyManager = new TestKeyManager();
    // We allow the keysize to be bigger than 16 since proto serialized adds some overhead.
    assertThat(
            keyManager
                .newKeyData(AesGcmKeyFormat.newBuilder().setKeySize(16).build().toByteString())
                .getValue()
                .size())
        .isAtLeast(16);
  }

  @Test
  public void newKeyData_keyMaterialTypeCorrect() throws Exception {
    TestKeyManager keyManager = new TestKeyManager();
    assertThat(
            keyManager
                .newKeyData(AesGcmKeyFormat.newBuilder().setKeySize(16).build().toByteString())
                .getKeyMaterialType())
        .isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void getPrimitiveClass() throws Exception {
    TestKeyManager keyManager = new TestKeyManager();
    assertThat(keyManager.getPrimitiveClass()).isEqualTo(Aead.class);
  }
}
