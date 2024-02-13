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
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@link MutablePrimitiveRegistryTest}.
 *
 * <p>We repeat the main tests in PrimitiveRegistryTest. There really shouldn't be both classes, but
 * currently this is what we need, and the other is what we should have.
 */
@RunWith(JUnit4.class)
public final class MutablePrimitiveRegistryTest {
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

  private static MutablePrimitiveRegistryTest.TestPrimitiveA getPrimitiveAKey1(
      MutablePrimitiveRegistryTest.TestKey1 key) {
    return new MutablePrimitiveRegistryTest.TestPrimitiveA();
  }

  private static MutablePrimitiveRegistryTest.TestPrimitiveA getPrimitiveAKey2(
      MutablePrimitiveRegistryTest.TestKey2 key) {
    return new MutablePrimitiveRegistryTest.TestPrimitiveA();
  }

  private static MutablePrimitiveRegistryTest.TestPrimitiveB getPrimitiveBKey1(
      MutablePrimitiveRegistryTest.TestKey1 key) {
    return new MutablePrimitiveRegistryTest.TestPrimitiveB();
  }

  private static MutablePrimitiveRegistryTest.TestPrimitiveB getPrimitiveBKey2(
      MutablePrimitiveRegistryTest.TestKey2 key) {
    return new MutablePrimitiveRegistryTest.TestPrimitiveB();
  }

  @Immutable
  private static final class TestWrapperA
      implements PrimitiveWrapper<TestPrimitiveA, TestPrimitiveA> {

    @Override
    public TestPrimitiveA wrap(final PrimitiveSet<TestPrimitiveA> primitives)
        throws GeneralSecurityException {
      return new TestPrimitiveA();
    }

    @Override
    public Class<TestPrimitiveA> getPrimitiveClass() {
      return TestPrimitiveA.class;
    }

    @Override
    public Class<TestPrimitiveA> getInputPrimitiveClass() {
      return TestPrimitiveA.class;
    }
  }

  @Immutable
  private static final class TestWrapperB
      implements PrimitiveWrapper<TestPrimitiveA, TestPrimitiveB> {

    @Override
    public TestPrimitiveB wrap(final PrimitiveSet<TestPrimitiveA> primitives)
        throws GeneralSecurityException {
      return new TestPrimitiveB();
    }

    @Override
    public Class<TestPrimitiveB> getPrimitiveClass() {
      return TestPrimitiveB.class;
    }

    @Override
    public Class<TestPrimitiveA> getInputPrimitiveClass() {
      return TestPrimitiveA.class;
    }
  }

  @Test
  public void test_registerAll_checkDispatch() throws Exception {
    MutablePrimitiveRegistry registry = new MutablePrimitiveRegistry();

    registry.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            MutablePrimitiveRegistryTest::getPrimitiveAKey1, TestKey1.class, TestPrimitiveA.class));
    registry.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            MutablePrimitiveRegistryTest::getPrimitiveAKey2, TestKey2.class, TestPrimitiveA.class));
    registry.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            MutablePrimitiveRegistryTest::getPrimitiveBKey1, TestKey1.class, TestPrimitiveB.class));
    registry.registerPrimitiveConstructor(
        PrimitiveConstructor.create(
            MutablePrimitiveRegistryTest::getPrimitiveBKey2, TestKey2.class, TestPrimitiveB.class));

    assertThat(
            registry.getPrimitive(
                new MutablePrimitiveRegistryTest.TestKey1(),
                MutablePrimitiveRegistryTest.TestPrimitiveA.class))
        .isNotNull();
    assertThat(
            registry.getPrimitive(
                new MutablePrimitiveRegistryTest.TestKey2(),
                MutablePrimitiveRegistryTest.TestPrimitiveA.class))
        .isNotNull();
    assertThat(
            registry.getPrimitive(
                new MutablePrimitiveRegistryTest.TestKey1(),
                MutablePrimitiveRegistryTest.TestPrimitiveB.class))
        .isNotNull();
    assertThat(
            registry.getPrimitive(
                new MutablePrimitiveRegistryTest.TestKey2(),
                MutablePrimitiveRegistryTest.TestPrimitiveB.class))
        .isNotNull();
  }

  @Test
  public void test_emptyRegistry_throws() throws Exception {
    MutablePrimitiveRegistry registry = new MutablePrimitiveRegistry();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            registry.getPrimitive(
                new MutablePrimitiveRegistryTest.TestKey1(),
                MutablePrimitiveRegistryTest.TestPrimitiveA.class));
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.getInputPrimitiveClass(MutablePrimitiveRegistryTest.TestPrimitiveA.class));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            registry.wrap(
                PrimitiveSet.newBuilder(MutablePrimitiveRegistryTest.TestPrimitiveA.class).build(),
                MutablePrimitiveRegistryTest.TestPrimitiveA.class));
  }

  @Test
  public void test_registerAllWrappers_checkDispatch() throws Exception {
    MutablePrimitiveRegistry registry = new MutablePrimitiveRegistry();

    registry.registerPrimitiveWrapper(new TestWrapperA());
    registry.registerPrimitiveWrapper(new TestWrapperB());

    assertThat(registry.getInputPrimitiveClass(TestPrimitiveA.class))
        .isEqualTo(TestPrimitiveA.class);
    assertThat(registry.getInputPrimitiveClass(TestPrimitiveB.class))
        .isEqualTo(TestPrimitiveA.class);
    assertThat(
            registry.wrap(
                PrimitiveSet.newBuilder(TestPrimitiveA.class).build(), TestPrimitiveA.class))
        .isInstanceOf(TestPrimitiveA.class);
    assertThat(
            registry.wrap(
                PrimitiveSet.newBuilder(TestPrimitiveA.class).build(), TestPrimitiveB.class))
        .isInstanceOf(TestPrimitiveB.class);
  }
}
