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
import static java.util.concurrent.TimeUnit.SECONDS;

import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.PrivateKeyTypeManager;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Thread safety tests for {@link Registry}. */
@RunWith(JUnit4.class)
public final class RegistryMultithreadTest {
  private static class Primitive {}

  private static class TestKeyManager implements KeyManager<Primitive> {
    public TestKeyManager(String typeUrl) {
      this.typeUrl = typeUrl;
    }

    private final String typeUrl;

    @Override
    public Primitive getPrimitive(ByteString proto) throws GeneralSecurityException {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public Primitive getPrimitive(MessageLite proto) throws GeneralSecurityException {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public MessageLite newKey(ByteString template) throws GeneralSecurityException {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public MessageLite newKey(MessageLite template) throws GeneralSecurityException {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public boolean doesSupport(String typeUrl) {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public String getKeyType() {
      return this.typeUrl;
    }

    @Override
    public int getVersion() {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public Class<Primitive> getPrimitiveClass() {
      return Primitive.class;
    }
  }

  private static class TestKeyTypeManager extends KeyTypeManager<AesGcmKey> {
    private final String typeUrl;

    public TestKeyTypeManager(String typeUrl) {
      super(AesGcmKey.class);
      this.typeUrl = typeUrl;
    }

    @Override
    public String getKeyType() {
      return typeUrl;
    }

    @Override
    public int getVersion() {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public KeyMaterialType keyMaterialType() {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public void validateKey(AesGcmKey keyProto) throws GeneralSecurityException {}

    @Override
    public AesGcmKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      throw new UnsupportedOperationException("Not needed for test");
    }
  }

  private static class TestPublicKeyTypeManager extends KeyTypeManager<Ed25519PublicKey> {
    private final String typeUrl;

    public TestPublicKeyTypeManager(String typeUrl) {
      super(Ed25519PublicKey.class);
      this.typeUrl = typeUrl;
    }

    @Override
    public String getKeyType() {
      return typeUrl;
    }

    @Override
    public int getVersion() {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public KeyMaterialType keyMaterialType() {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public void validateKey(Ed25519PublicKey keyProto) throws GeneralSecurityException {}

    @Override
    public Ed25519PublicKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      throw new UnsupportedOperationException("Not needed for test");
    }
  }

  private static class TestPrivateKeyTypeManager
      extends PrivateKeyTypeManager<Ed25519PrivateKey, Ed25519PublicKey> {
    private final String typeUrl;

    public TestPrivateKeyTypeManager(String typeUrl) {
      super(Ed25519PrivateKey.class, Ed25519PublicKey.class);
      this.typeUrl = typeUrl;
    }

    @Override
    public String getKeyType() {
      return typeUrl;
    }

    @Override
    public int getVersion() {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public KeyMaterialType keyMaterialType() {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public void validateKey(Ed25519PrivateKey keyProto) throws GeneralSecurityException {}

    @Override
    public Ed25519PrivateKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public Ed25519PublicKey getPublicKey(Ed25519PrivateKey privateKey) {
      throw new UnsupportedOperationException("Not needed for test");
    }
  }

  @Test
  public void registerAndGetKeyManager_works() throws Exception {
    ExecutorService threadPool = Executors.newFixedThreadPool(4);
    List<Future<?>> futures = new ArrayList<>();
    Registry.registerKeyManager(new TestKeyManager("KeyManagerStart"), false);
    Registry.registerKeyManager(new TestKeyTypeManager("KeyTypeManagerStart"), false);
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager("PrivateKeyTypeManagerStart"),
        new TestPublicKeyTypeManager("PublicKeyTypeManagerStart"),
        false);
    futures.add(
        threadPool.submit(
            () -> {
              try {

                for (int i = 0; i < 100; ++i) {
                  Registry.registerKeyManager(new TestKeyManager("KeyManager" + i), false);
                }
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    futures.add(
        threadPool.submit(
            () -> {
              try {
                for (int i = 0; i < 100; ++i) {
                  Registry.registerKeyManager(new TestKeyTypeManager("KeyTypeManager" + i), false);
                }
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    futures.add(
        threadPool.submit(
            () -> {
              try {
                for (int i = 0; i < 100; ++i) {
                  Registry.registerAsymmetricKeyManagers(
                      new TestPrivateKeyTypeManager("Private" + i),
                      new TestPublicKeyTypeManager("Public" + i),
                      false);
                }
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    futures.add(
        threadPool.submit(
            () -> {
              try {
                for (int i = 0; i < 100; ++i) {

                  Registry.getKeyManager("KeyManagerStart");
                  Registry.getKeyManager("KeyTypeManagerStart");
                  Registry.getKeyManager("PrivateKeyTypeManagerStart");
                  Registry.getKeyManager("PublicKeyTypeManagerStart");
                }
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));

    threadPool.shutdown();
    assertThat(threadPool.awaitTermination(300, SECONDS)).isTrue();
    for (int i = 0; i < futures.size(); ++i) {
      futures.get(i).get(); // This will throw an exception if the thread threw an exception.
    }
  }

  // TODO(tholenst): Epxand the test coverage for primitive wrappers and catalogues.
}
