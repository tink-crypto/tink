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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link PrimitiveRegistry}. */
@RunWith(JUnit4.class)
public final class PrimitiveRegistryTest {
  // ===============================================================================================
  // SETUP:
  // We create 2 different key classes (TestKey1, TestKey2) and two different primitive classes
  // (TestPrimitiveA, TestPrimitiveB), and provide ways to create both primitives with both keys.
  //
  // For this, we provide the methods getPrimitive{A,B}Key{1,2}. The method getPrimitiveBKey1 then
  // uses the key of type TestKey1 to create a primitive of type TestPrimitiveB.
  //
  // Note that calling these multiple times will give different objects (which allows us to test
  // that registering different objects for the same task fails).
  // ===============================================================================================

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

  private static TestPrimitiveA getPrimitiveAKey1(TestKey1 key) {
    return new TestPrimitiveA();
  }

  private static TestPrimitiveA getPrimitiveAKey2(TestKey2 key) {
    return new TestPrimitiveA();
  }

  private static TestPrimitiveB getPrimitiveBKey1(TestKey1 key) {
    return new TestPrimitiveB();
  }

  private static TestPrimitiveB getPrimitiveBKey2(TestKey2 key) {
    return new TestPrimitiveB();
  }

  @Test
  public void test_registerConstructorAndGet() throws Exception {
    PrimitiveRegistry registry =
        new PrimitiveRegistry.Builder()
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    PrimitiveRegistryTest::getPrimitiveAKey1,
                    TestKey1.class,
                    TestPrimitiveA.class))
            .build();
    assertThat(registry.getPrimitive(new TestKey1(), TestPrimitiveA.class)).isNotNull();
  }

  @Test
  public void test_emptyRegistry_throws() throws Exception {
    PrimitiveRegistry registry = new PrimitiveRegistry.Builder().build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.getPrimitive(new TestKey1(), TestPrimitiveA.class));
  }

  @Test
  public void test_registerSameSerializerTwice_works() throws Exception {
    PrimitiveConstructor<TestKey1, TestPrimitiveA> testPrimitiveConstructor =
        PrimitiveConstructor.create(
            PrimitiveRegistryTest::getPrimitiveAKey1, TestKey1.class, TestPrimitiveA.class);
    PrimitiveRegistry unused = new PrimitiveRegistry.Builder()
        .registerPrimitiveConstructor(testPrimitiveConstructor)
        .registerPrimitiveConstructor(testPrimitiveConstructor)
        .build();
  }

  @Test
  public void test_registerDifferentSerializerWithSameKeyType_throws() throws Exception {
    PrimitiveConstructor<TestKey1, TestPrimitiveA> testPrimitiveConstructor1 =
        PrimitiveConstructor.create(
            PrimitiveRegistryTest::getPrimitiveAKey1, TestKey1.class, TestPrimitiveA.class);
    PrimitiveConstructor<TestKey1, TestPrimitiveA> testPrimitiveConstructor2 =
        PrimitiveConstructor.create(
            PrimitiveRegistryTest::getPrimitiveAKey1, TestKey1.class, TestPrimitiveA.class);
    PrimitiveRegistry.Builder builder = new PrimitiveRegistry.Builder();
    builder.registerPrimitiveConstructor(testPrimitiveConstructor1);
    assertThrows(
        GeneralSecurityException.class,
        () -> builder.registerPrimitiveConstructor(testPrimitiveConstructor2));
  }

  @Test
  public void test_registerDifferentSerializerWithDifferentKeyType_works() throws Exception {
    PrimitiveConstructor<TestKey1, TestPrimitiveA> testPrimitiveConstructor1 =
        PrimitiveConstructor.create(
            PrimitiveRegistryTest::getPrimitiveAKey1, TestKey1.class, TestPrimitiveA.class);
    PrimitiveConstructor<TestKey2, TestPrimitiveA> testPrimitiveConstructor2 =
        PrimitiveConstructor.create(
            PrimitiveRegistryTest::getPrimitiveAKey2, TestKey2.class, TestPrimitiveA.class);
    PrimitiveRegistry unused = new PrimitiveRegistry.Builder()
        .registerPrimitiveConstructor(testPrimitiveConstructor1)
        .registerPrimitiveConstructor(testPrimitiveConstructor2)
        .build();
  }

  @Test
  public void test_registerDifferentSerializerWithDifferentPrimitiveType_works()
      throws Exception {
    PrimitiveConstructor<TestKey1, TestPrimitiveA> testPrimitiveConstructor1 =
        PrimitiveConstructor.create(
            PrimitiveRegistryTest::getPrimitiveAKey1, TestKey1.class, TestPrimitiveA.class);
    PrimitiveConstructor<TestKey1, TestPrimitiveB> testPrimitiveConstructor2 =
        PrimitiveConstructor.create(
            PrimitiveRegistryTest::getPrimitiveBKey1, TestKey1.class, TestPrimitiveB.class);
    PrimitiveRegistry unused = new PrimitiveRegistry.Builder()
        .registerPrimitiveConstructor(testPrimitiveConstructor1)
        .registerPrimitiveConstructor(testPrimitiveConstructor2)
        .build();
  }

  @Test
  public void test_registerAll_checkDispatch() throws Exception {
    PrimitiveRegistry registry =
        new PrimitiveRegistry.Builder()
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    PrimitiveRegistryTest::getPrimitiveAKey1,
                    TestKey1.class,
                    TestPrimitiveA.class))
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    PrimitiveRegistryTest::getPrimitiveAKey2,
                    TestKey2.class,
                    TestPrimitiveA.class))
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    PrimitiveRegistryTest::getPrimitiveBKey1,
                    TestKey1.class,
                    TestPrimitiveB.class))
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    PrimitiveRegistryTest::getPrimitiveBKey2,
                    TestKey2.class,
                    TestPrimitiveB.class))
            .build();
    assertThat(
        registry
            .getPrimitive(new TestKey1(), TestPrimitiveA.class)).isInstanceOf(TestPrimitiveA.class);
    assertThat(
        registry
            .getPrimitive(new TestKey2(), TestPrimitiveA.class)).isInstanceOf(TestPrimitiveA.class);
    assertThat(
        registry
            .getPrimitive(new TestKey1(), TestPrimitiveB.class)).isInstanceOf(TestPrimitiveB.class);
    assertThat(
        registry
            .getPrimitive(new TestKey2(), TestPrimitiveB.class)).isInstanceOf(TestPrimitiveB.class);
  }

  @Test
  public void test_serializer_copyWorks() throws Exception {
    PrimitiveRegistry registry =
        new PrimitiveRegistry.Builder()
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    PrimitiveRegistryTest::getPrimitiveAKey1,
                    TestKey1.class,
                    TestPrimitiveA.class))
            .build();
    PrimitiveRegistry registry2 = new PrimitiveRegistry.Builder(registry).build();
    assertThat(registry2.getPrimitive(new TestKey1(), TestPrimitiveA.class))
        .isInstanceOf(TestPrimitiveA.class);
  }
  
  @Test
  public void test_copyDoesNotChangeOldVersion() throws Exception {
    PrimitiveRegistry registry1 = new PrimitiveRegistry.Builder().build();
    PrimitiveRegistry.Builder builder = new PrimitiveRegistry.Builder(registry1);
    PrimitiveRegistry registry2 = builder.build();
    builder.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            PrimitiveRegistryTest::getPrimitiveAKey1, TestKey1.class, TestPrimitiveA.class));
    assertThrows(
        GeneralSecurityException.class,
        () -> registry1.getPrimitive(new TestKey1(), TestPrimitiveA.class));
    assertThrows(
        GeneralSecurityException.class,
        () -> registry2.getPrimitive(new TestKey1(), TestPrimitiveA.class));
  }
}
