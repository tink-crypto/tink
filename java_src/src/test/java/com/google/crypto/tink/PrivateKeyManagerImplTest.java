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
import static com.google.crypto.tink.testing.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests the methods implemented in KeyManagerImpl using the concrete implementation above. */
@RunWith(JUnit4.class)
public final class PrivateKeyManagerImplTest {

  private static class TestPublicKeyTypeManager extends KeyTypeManager<Ed25519PublicKey> {
    public TestPublicKeyTypeManager() {
      super(Ed25519PublicKey.class);
    }

    @Override
    public String getKeyType() {
      return "type.googleapis.com/google.crypto.tink.Ed25519PublicKey";
    }

    @Override
    public int getVersion() {
      return 1;
    }

    @Override
    public KeyMaterialType keyMaterialType() {
      return KeyMaterialType.ASYMMETRIC_PUBLIC;
    }

    @Override
    public void validateKey(Ed25519PublicKey keyProto) throws GeneralSecurityException {
      if (keyProto.getKeyValue().size() != 32) {
        throw new GeneralSecurityException("validateKey(Ed25519PublicKey) failed");
      }
    }

    @Override
    public Ed25519PublicKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      return Ed25519PublicKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    }
  }

  private static class TestPrivateKeyTypeManager
      extends PrivateKeyTypeManager<Ed25519PrivateKey, Ed25519PublicKey> {
    public TestPrivateKeyTypeManager() {
      super(Ed25519PrivateKey.class, Ed25519PublicKey.class);
    }

    @Override
    public String getKeyType() {
      return "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";
    }

    @Override
    public int getVersion() {
      return 1;
    }

    @Override
    public KeyMaterialType keyMaterialType() {
      return KeyMaterialType.ASYMMETRIC_PRIVATE;
    }

    @Override
    public void validateKey(Ed25519PrivateKey keyProto) throws GeneralSecurityException {
      // Throw by hand so we can verify the exception comes from here.
      if (keyProto.getKeyValue().size() != 32) {
        throw new GeneralSecurityException("validateKey(Ed25519PrivateKey) failed");
      }
    }

    @Override
    public Ed25519PrivateKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      return Ed25519PrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    }

    @Override
    public Ed25519PublicKey getPublicKey(Ed25519PrivateKey privateKey) {
      return privateKey.getPublicKey();
    }
  }

  @Test
  public void getPublicKeyData_works() throws Exception {
    TestPrivateKeyTypeManager privateManager = new TestPrivateKeyTypeManager();
    TestPublicKeyTypeManager publicManager = new TestPublicKeyTypeManager();
    PrivateKeyManager<Void> manager =
        new PrivateKeyManagerImpl<>(privateManager, publicManager, Void.class);
    Ed25519PrivateKey privateKey =
        Ed25519PrivateKey.newBuilder()
            .setPublicKey(
                Ed25519PublicKey.newBuilder()
                    .setKeyValue(ByteString.copyFrom(Random.randBytes(32))))
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .build();

    KeyData keyData = manager.getPublicKeyData(privateKey.toByteString());

    assertThat(keyData.getTypeUrl())
        .isEqualTo("type.googleapis.com/google.crypto.tink.Ed25519PublicKey");
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(publicKey).isEqualTo(privateKey.getPublicKey());
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
  }

  @Test
  public void getPublicKeyData_invalidPrivateKey_throws() throws Exception {
    TestPrivateKeyTypeManager privateManager = new TestPrivateKeyTypeManager();
    TestPublicKeyTypeManager publicManager = new TestPublicKeyTypeManager();
    PrivateKeyManager<Void> manager =
        new PrivateKeyManagerImpl<>(privateManager, publicManager, Void.class);
    Ed25519PrivateKey privateKey =
        Ed25519PrivateKey.newBuilder()
            .setPublicKey(
                Ed25519PublicKey.newBuilder()
                    .setKeyValue(ByteString.copyFrom(Random.randBytes(32))))
            .setKeyValue(ByteString.copyFrom(Random.randBytes(33)))
            .build();
    ByteString privateKeyByteString = privateKey.toByteString();

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> manager.getPublicKeyData(privateKeyByteString));
    assertExceptionContains(e, "validateKey(Ed25519PrivateKey)");
  }

  @Test
  public void getPublicKeyData_invalidPublicKey_throws() throws Exception {
    TestPrivateKeyTypeManager privateManager = new TestPrivateKeyTypeManager();
    TestPublicKeyTypeManager publicManager = new TestPublicKeyTypeManager();
    PrivateKeyManager<Void> manager =
        new PrivateKeyManagerImpl<>(privateManager, publicManager, Void.class);
    Ed25519PrivateKey privateKey =
        Ed25519PrivateKey.newBuilder()
            .setPublicKey(
                Ed25519PublicKey.newBuilder()
                    .setKeyValue(ByteString.copyFrom(Random.randBytes(33))))
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .build();
    ByteString privateKeyByteString = privateKey.toByteString();

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> manager.getPublicKeyData(privateKeyByteString));
    assertExceptionContains(e, "validateKey(Ed25519PublicKey)");
  }
}
