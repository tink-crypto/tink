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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.SECONDS;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Thread safety tests for {@link MutableSerializationRegistry}. */
@RunWith(JUnit4.class)
public final class MutableSerializationRegistryMultithreadTest {
  private static final SecretKeyAccess ACCESS = InsecureSecretKeyAccess.get();

  private static final Bytes A_1 = Bytes.copyFrom("0".getBytes(UTF_8));
  private static final Bytes A_2 = Bytes.copyFrom("1".getBytes(UTF_8));
  private static final Bytes B_1 = Bytes.copyFrom("1".getBytes(UTF_8));
  private static final Bytes B_2 = Bytes.copyFrom("2".getBytes(UTF_8));

  @Immutable
  private static final class TestParameters1 extends Parameters {
    @Override
    public boolean hasIdRequirement() {
      return false;
    }
  }

  @Immutable
  private static final class TestParameters2 extends Parameters {
    @Override
    public boolean hasIdRequirement() {
      return false;
    }
  }

  @Immutable
  private static final class TestKey1 extends Key {
    @Override
    public Parameters getParameters() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    public boolean equalsKey(Key other) {
      throw new UnsupportedOperationException("Not needed in test");
    }
  }

  @Immutable
  private static final class TestKey2 extends Key {
    @Override
    public Parameters getParameters() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    public boolean equalsKey(Key other) {
      throw new UnsupportedOperationException("Not needed in test");
    }
  }

  @Immutable
  private static final class TestSerializationA implements Serialization {
    public TestSerializationA(Bytes objectIdentifier) {
      this.objectIdentifier = objectIdentifier;
    }

    private final Bytes objectIdentifier;

    @Override
    public Bytes getObjectIdentifier() {
      return objectIdentifier;
    }
  }

  @Immutable
  private static final class TestSerializationB implements Serialization {
    public TestSerializationB(Bytes objectIdentifier) {
      this.objectIdentifier = objectIdentifier;
    }

    private final Bytes objectIdentifier;

    @Override
    public Bytes getObjectIdentifier() {
      return objectIdentifier;
    }
  }

  private static TestSerializationA serializeKey1ToA(TestKey1 key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    SecretKeyAccess.requireAccess(access);
    return new TestSerializationA(A_1);
  }

  private static TestSerializationA serializeKey2ToA(TestKey2 key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    SecretKeyAccess.requireAccess(access);
    return new TestSerializationA(A_2);
  }

  private static TestSerializationB serializeKey1ToB(TestKey1 key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    SecretKeyAccess.requireAccess(access);
    return new TestSerializationB(B_1);
  }

  private static TestSerializationB serializeKey2ToB(TestKey2 key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    SecretKeyAccess.requireAccess(access);
    return new TestSerializationB(B_2);
  }

  private static Key parseAToKey1(
      TestSerializationA serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!A_1.equals(serialization.getObjectIdentifier())) {
      throw new GeneralSecurityException("Wrong object identifier");
    }
    SecretKeyAccess.requireAccess(access);
    return new TestKey1();
  }

  private static Key parseBToKey1(
      TestSerializationB serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!B_1.equals(serialization.getObjectIdentifier())) {
      throw new GeneralSecurityException("Wrong object identifier");
    }
    SecretKeyAccess.requireAccess(access);
    return new TestKey1();
  }

  private static TestSerializationA serializeParameters1ToA(TestParameters1 parameters)
      throws GeneralSecurityException {
    return new TestSerializationA(A_1);
  }

  private static TestSerializationA serializeParameters2ToA(TestParameters2 parameters)
      throws GeneralSecurityException {
    return new TestSerializationA(A_2);
  }

  private static TestSerializationB serializeParameters1ToB(TestParameters1 parameters)
      throws GeneralSecurityException {
    return new TestSerializationB(B_1);
  }

  private static TestSerializationB serializeParameters2ToB(TestParameters2 parameters)
      throws GeneralSecurityException {
    return new TestSerializationB(B_2);
  }

  private static Parameters parseAToParameters1(TestSerializationA serialization)
      throws GeneralSecurityException {
    if (!A_1.equals(serialization.getObjectIdentifier())) {
      throw new GeneralSecurityException("Wrong object identifier");
    }
    return new TestParameters1();
  }

  private static Parameters parseBToParameters1(TestSerializationB serialization)
      throws GeneralSecurityException {
    if (!B_1.equals(serialization.getObjectIdentifier())) {
      throw new GeneralSecurityException("Wrong object identifier");
    }
    return new TestParameters1();
  }

  private static final int REPETITIONS = 1000;

  @Test
  public void registerAndParseAndSerializeInParallel_works() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    ExecutorService threadPool = Executors.newFixedThreadPool(4);
    List<Future<?>> futures = new ArrayList<>();
    registry.registerKeySerializer(
        KeySerializer.create(
            MutableSerializationRegistryMultithreadTest::serializeKey1ToA,
            TestKey1.class,
            TestSerializationA.class));
    registry.registerKeyParser(
        KeyParser.create(
            MutableSerializationRegistryMultithreadTest::parseAToKey1,
            A_1,
            TestSerializationA.class));
    registry.registerParametersSerializer(
        ParametersSerializer.create(
            MutableSerializationRegistryMultithreadTest::serializeParameters1ToA,
            TestParameters1.class,
            TestSerializationA.class));
    registry.registerParametersParser(
        ParametersParser.create(
            MutableSerializationRegistryMultithreadTest::parseAToParameters1,
            A_1,
            TestSerializationA.class));

    futures.add(
        threadPool.submit(
            () -> {
              try {
                for (int i = 0; i < REPETITIONS; ++i) {
                  registry.registerKeyParser(
                      KeyParser.create(
                          MutableSerializationRegistryMultithreadTest::parseAToKey1,
                          Bytes.copyFrom(ByteBuffer.allocate(4).putInt(i).array()),
                          TestSerializationA.class));
                }
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    futures.add(
        threadPool.submit(
            () -> {
              try {
                // This thread mainly wants to do a key serializer registration, but we only have
                // one of those, since each needs either a new serialization class, or a new key
                // class. So first do a few parsing registrations to mix things up.
                for (int i = 0; i < REPETITIONS / 2; ++i) {
                  registry.registerKeyParser(
                      KeyParser.create(
                          MutableSerializationRegistryMultithreadTest::parseBToKey1,
                          Bytes.copyFrom(ByteBuffer.allocate(4).putInt(i).array()),
                          TestSerializationB.class));
                }
                registry.registerKeySerializer(
                    KeySerializer.create(
                        MutableSerializationRegistryMultithreadTest::serializeKey2ToA,
                        TestKey2.class,
                        TestSerializationA.class));
                registry.registerKeySerializer(
                    KeySerializer.create(
                        MutableSerializationRegistryMultithreadTest::serializeKey2ToB,
                        TestKey2.class,
                        TestSerializationB.class));
                registry.registerKeySerializer(
                    KeySerializer.create(
                        MutableSerializationRegistryMultithreadTest::serializeKey1ToB,
                        TestKey1.class,
                        TestSerializationB.class));
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    futures.add(
        threadPool.submit(
            () -> {
              try {
                for (int i = 0; i < REPETITIONS; ++i) {
                  registry.parseKey(new TestSerializationA(A_1), ACCESS);
                }
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    futures.add(
        threadPool.submit(
            () -> {
              try {
                for (int i = 0; i < REPETITIONS; ++i) {
                  registry.serializeKey(new TestKey1(), TestSerializationA.class, ACCESS);
                }
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    // =============================== More threads doing the same thing, this time for parameters.
    futures.add(
        threadPool.submit(
            () -> {
              try {
                for (int i = 0; i < REPETITIONS; ++i) {
                  registry.registerParametersParser(
                      ParametersParser.create(
                          MutableSerializationRegistryMultithreadTest::parseAToParameters1,
                          Bytes.copyFrom(ByteBuffer.allocate(4).putInt(i).array()),
                          TestSerializationA.class));
                }
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    futures.add(
        threadPool.submit(
            () -> {
              try {
                // This thread mainly wants to do a key serializer registration, but we only have
                // one of those, since each needs either a new serialization class, or a new key
                // class. So first do a few parsing registrations to mix things up.
                for (int i = 0; i < REPETITIONS / 2; ++i) {
                  registry.registerParametersParser(
                      ParametersParser.create(
                          MutableSerializationRegistryMultithreadTest::parseBToParameters1,
                          Bytes.copyFrom(ByteBuffer.allocate(4).putInt(i).array()),
                          TestSerializationB.class));
                }
                registry.registerParametersSerializer(
                    ParametersSerializer.create(
                        MutableSerializationRegistryMultithreadTest::serializeParameters2ToA,
                        TestParameters2.class,
                        TestSerializationA.class));
                registry.registerParametersSerializer(
                    ParametersSerializer.create(
                        MutableSerializationRegistryMultithreadTest::serializeParameters2ToB,
                        TestParameters2.class,
                        TestSerializationB.class));
                registry.registerParametersSerializer(
                    ParametersSerializer.create(
                        MutableSerializationRegistryMultithreadTest::serializeParameters1ToB,
                        TestParameters1.class,
                        TestSerializationB.class));
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));

    futures.add(
        threadPool.submit(
            () -> {
              try {
                for (int i = 0; i < REPETITIONS; ++i) {
                  registry.parseParameters(new TestSerializationA(A_1));
                }
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    futures.add(
        threadPool.submit(
            () -> {
              try {
                for (int i = 0; i < REPETITIONS; ++i) {
                  registry.serializeParameters(new TestParameters1(), TestSerializationA.class);
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
}
