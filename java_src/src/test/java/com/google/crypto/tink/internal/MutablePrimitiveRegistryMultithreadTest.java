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
import static java.util.concurrent.TimeUnit.SECONDS;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.errorprone.annotations.Immutable;
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

@RunWith(JUnit4.class)
public class MutablePrimitiveRegistryMultithreadTest {
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
  private static final class TestPrimitiveA {
    public TestPrimitiveA() {}
  }

  @Immutable
  private static final class TestPrimitiveB {
    public TestPrimitiveB() {}
  }

  private static MutablePrimitiveRegistryMultithreadTest.TestPrimitiveA getPrimitiveAKey1(
      MutablePrimitiveRegistryMultithreadTest.TestKey1 key) {
    return new MutablePrimitiveRegistryMultithreadTest.TestPrimitiveA();
  }

  private static MutablePrimitiveRegistryMultithreadTest.TestPrimitiveA getPrimitiveAKey2(
      MutablePrimitiveRegistryMultithreadTest.TestKey2 key) {
    return new MutablePrimitiveRegistryMultithreadTest.TestPrimitiveA();
  }

  private static MutablePrimitiveRegistryMultithreadTest.TestPrimitiveB getPrimitiveBKey1(
      MutablePrimitiveRegistryMultithreadTest.TestKey1 key) {
    return new MutablePrimitiveRegistryMultithreadTest.TestPrimitiveB();
  }

  private static MutablePrimitiveRegistryMultithreadTest.TestPrimitiveB getPrimitiveBKey2(
      MutablePrimitiveRegistryMultithreadTest.TestKey2 key) {
    return new MutablePrimitiveRegistryMultithreadTest.TestPrimitiveB();
  }

  private static final int REPETITIONS = 10000;
  private static final int THREAD_NUMBER = 12;

  @Test
  public void registerAndGetPrimitivesInParallel_works() throws Exception {
    MutablePrimitiveRegistry registry = new MutablePrimitiveRegistry();
    ExecutorService threadPool = Executors.newFixedThreadPool(THREAD_NUMBER);
    List<Future<?>> futures = new ArrayList<>();
    registry.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            MutablePrimitiveRegistryMultithreadTest::getPrimitiveAKey1,
            TestKey1.class,
            TestPrimitiveA.class));

    // It's questionable how mixed up things are gonna be with so few registrations but
    // registering many constructors would require around square as many of both key and
    // primitive test classes created, and that's gonna be a serious code bloat.
    futures.add(
        threadPool.submit(
            () -> {
              try {
                registry.registerPrimitiveConstructor(
                    PrimitiveConstructor.create(
                        MutablePrimitiveRegistryMultithreadTest::getPrimitiveAKey2,
                        TestKey2.class,
                        TestPrimitiveA.class));
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    futures.add(
        threadPool.submit(
            () -> {
              try {
                registry.registerPrimitiveConstructor(
                    PrimitiveConstructor.create(
                        MutablePrimitiveRegistryMultithreadTest::getPrimitiveBKey1,
                        TestKey1.class,
                        TestPrimitiveB.class));
                registry.registerPrimitiveConstructor(
                    PrimitiveConstructor.create(
                        MutablePrimitiveRegistryMultithreadTest::getPrimitiveBKey2,
                        TestKey2.class,
                        TestPrimitiveB.class));
              } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
              }
            }));
    // Thread pool size - the number of registration threads.
    for (int i = 0; i < THREAD_NUMBER - 2; ++i) {
      futures.add(
          threadPool.submit(
              () -> {
                try {
                  for (int j = 0; j < REPETITIONS; ++j) {
                    TestPrimitiveA unused =
                        registry.getPrimitive(new TestKey1(), TestPrimitiveA.class);
                  }
                } catch (GeneralSecurityException e) {
                  throw new RuntimeException(e);
                }
              }));
    }

    threadPool.shutdown();
    assertThat(threadPool.awaitTermination(300, SECONDS)).isTrue();
    for (Future<?> future : futures) {
      future.get(); // This will throw an exception if the thread threw an exception.
    }
  }
}
