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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link InternalConfiguration}. */
@RunWith(JUnit4.class)
public class InternalConfigurationTest {
  // Test classes which we can populate PrimitiveRegistry instances with.
  @Immutable
  private static final class TestKey1 extends Key {
    @Override
    public Parameters getParameters() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
      return null;
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

    private final Key key;

    public TestPrimitiveA() {
      this.key = null;
    }

    public TestPrimitiveA(Key key) {
      this.key = key;
    }

    public Key getKey() {
      return key;
    }
  }

  @Immutable
  private static final class TestPrimitiveB {
    public TestPrimitiveB() {}
  }

  @Immutable
  private static final class TestWrapperA
      implements PrimitiveWrapper<TestPrimitiveA, TestPrimitiveA> {

    @Override
    public TestPrimitiveA wrap(final PrimitiveSet<TestPrimitiveA> primitives) {
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
      implements PrimitiveWrapper<TestPrimitiveB, TestPrimitiveB> {

    @Override
    public TestPrimitiveB wrap(final PrimitiveSet<TestPrimitiveB> primitives) {
      return new TestPrimitiveB();
    }

    @Override
    public Class<TestPrimitiveB> getPrimitiveClass() {
      return TestPrimitiveB.class;
    }

    @Override
    public Class<TestPrimitiveB> getInputPrimitiveClass() {
      return TestPrimitiveB.class;
    }
  }

  private static TestPrimitiveA getPrimitiveAKey1(TestKey1 key) {
    return new TestPrimitiveA(key);
  }

  private static TestPrimitiveA getPrimitiveAKey2(TestKey2 key) {
    return new TestPrimitiveA(key);
  }

  private static TestPrimitiveB getPrimitiveBKey1(TestKey1 key) {
    return new TestPrimitiveB();
  }

  private static TestPrimitiveB getPrimitiveBKey2(TestKey2 key) {
    return new TestPrimitiveB();
  }

  @Test
  public void getLegacyPrimitive_throws() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder()
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    InternalConfigurationTest::getPrimitiveAKey1,
                    TestKey1.class,
                    TestPrimitiveA.class))
            .build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);

    assertThrows(
        UnsupportedOperationException.class,
        () ->
            configuration.getLegacyPrimitive(
                KeyData.newBuilder()
                    .setValue(
                        ByteString.copyFrom(
                            SecretBytes.randomBytes(32).toByteArray(InsecureSecretKeyAccess.get())))
                    .setTypeUrl("type.googleapis.com/google.crypto.tink.HmacKey")
                    .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
                    .build(),
                TestPrimitiveA.class));
  }

  @Test
  public void getPrimitive_works() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder()
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    InternalConfigurationTest::getPrimitiveAKey1,
                    TestKey1.class,
                    TestPrimitiveA.class))
            .build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);
    TestKey1 key = new TestKey1();

    TestPrimitiveA primitive = configuration.getPrimitive(key, TestPrimitiveA.class);

    assertThat(primitive.getKey()).isEqualTo(key);
  }

  @Test
  public void wrap_works() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder().registerPrimitiveWrapper(new TestWrapperA()).build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);

    // Check that the type is as expected.
    TestPrimitiveA unused = configuration.wrap(
                PrimitiveSet.newBuilder(TestPrimitiveA.class).build(), TestPrimitiveA.class);
  }

  @Test
  public void getInputPrimitiveClass_works() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder().registerPrimitiveWrapper(new TestWrapperA()).build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);

    assertThat(configuration.getInputPrimitiveClass(TestPrimitiveA.class))
        .isEqualTo(TestPrimitiveA.class);
  }

  @Test
  public void getPrimitive_dispatchWorks() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder()
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    InternalConfigurationTest::getPrimitiveAKey1,
                    TestKey1.class,
                    TestPrimitiveA.class))
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    InternalConfigurationTest::getPrimitiveAKey2,
                    TestKey2.class,
                    TestPrimitiveA.class))
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    InternalConfigurationTest::getPrimitiveBKey1,
                    TestKey1.class,
                    TestPrimitiveB.class))
            .build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);
    TestKey1 key1 = new TestKey1();
    TestKey2 key2 = new TestKey2();

    TestPrimitiveA primitiveAKey1 = configuration.getPrimitive(key1, TestPrimitiveA.class);
    TestPrimitiveA primitiveAKey2 = configuration.getPrimitive(key2, TestPrimitiveA.class);

    assertThat(primitiveAKey1.getKey()).isEqualTo(key1);
    assertThat(primitiveAKey2.getKey()).isEqualTo(key2);
    // Check that the resulting primitive is of the expected type.
    TestPrimitiveB unused = configuration.getPrimitive(key1, TestPrimitiveB.class);
  }

  @Test
  public void wrap_dispatchWorks() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder()
            .registerPrimitiveWrapper(new TestWrapperA())
            .registerPrimitiveWrapper(new TestWrapperB())
            .build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);

    // Check that the wrapped primitives are of the expected types.
    TestPrimitiveA unusedA = configuration.wrap(
                PrimitiveSet.newBuilder(TestPrimitiveA.class).build(), TestPrimitiveA.class);
    TestPrimitiveB unusedB = configuration.wrap(
                PrimitiveSet.newBuilder(TestPrimitiveB.class).build(), TestPrimitiveB.class);
  }

  @Test
  public void getInputPrimitiveClass_dispatchWorks() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder()
            .registerPrimitiveWrapper(new TestWrapperA())
            .registerPrimitiveWrapper(new TestWrapperB())
            .build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);

    assertThat(configuration.getInputPrimitiveClass(TestPrimitiveA.class))
        .isEqualTo(TestPrimitiveA.class);
    assertThat(configuration.getInputPrimitiveClass(TestPrimitiveB.class))
        .isEqualTo(TestPrimitiveB.class);
  }

  @Test
  public void getPrimitive_unregisteredKeyTypeThrows() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder()
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    InternalConfigurationTest::getPrimitiveAKey1,
                    TestKey1.class,
                    TestPrimitiveA.class))
            .build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);
    TestKey2 wrongClassKey = new TestKey2();

    assertThrows(
        GeneralSecurityException.class,
        () -> configuration.getPrimitive(wrongClassKey, TestPrimitiveA.class));
  }

  @Test
  public void getPrimitive_unregisteredPrimitiveClassThrows() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder()
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    InternalConfigurationTest::getPrimitiveAKey1,
                    TestKey1.class,
                    TestPrimitiveA.class))
            .build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);
    TestKey1 correctClassKey = new TestKey1();

    assertThrows(
        GeneralSecurityException.class,
        () -> configuration.getPrimitive(correctClassKey, TestPrimitiveB.class));
  }

  @Test
  public void getPrimitive_wrongPrimitiveKeyClassCombinationThrows() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder()
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    InternalConfigurationTest::getPrimitiveAKey1,
                    TestKey1.class,
                    TestPrimitiveA.class))
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    InternalConfigurationTest::getPrimitiveBKey2,
                    TestKey2.class,
                    TestPrimitiveB.class))
            .build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);

    assertThrows(
        GeneralSecurityException.class,
        () -> configuration.getPrimitive(new TestKey1(), TestPrimitiveB.class));
    assertThrows(
        GeneralSecurityException.class,
        () -> configuration.getPrimitive(new TestKey2(), TestPrimitiveA.class));
  }

  @Test
  public void wrap_wrongInputPrimitiveClassThrows() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder().registerPrimitiveWrapper(new TestWrapperA()).build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            configuration.wrap(
                PrimitiveSet.newBuilder(TestPrimitiveB.class).build(), TestPrimitiveA.class));
  }

  @Test
  public void wrap_unregisteredWrapperClassThrows() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder().registerPrimitiveWrapper(new TestWrapperA()).build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            configuration.wrap(
                PrimitiveSet.newBuilder(TestPrimitiveA.class).build(), TestPrimitiveB.class));
  }

  @Test
  public void getInputPrimitiveClass_unregisteredWrapperClassThrows() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder().registerPrimitiveWrapper(new TestWrapperA()).build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);

    assertThrows(
        GeneralSecurityException.class,
        () -> configuration.getInputPrimitiveClass(TestPrimitiveB.class));
  }

  @Test
  public void emptyRegistry_throws() {
    PrimitiveRegistry registry = PrimitiveRegistry.builder().build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);

    assertThrows(
        GeneralSecurityException.class,
        () -> configuration.getPrimitive(new TestKey1(), TestPrimitiveA.class));
    assertThrows(
        GeneralSecurityException.class,
        () -> configuration.getInputPrimitiveClass(TestPrimitiveA.class));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            configuration.wrap(
                PrimitiveSet.newBuilder(TestPrimitiveA.class).build(), TestPrimitiveA.class));
  }
}
