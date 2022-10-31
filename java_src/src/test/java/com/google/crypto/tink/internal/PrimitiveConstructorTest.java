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

import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.errorprone.annotations.Immutable;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class PrimitiveConstructorTest {
  @Immutable
  private static final class TestKey extends Key {
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
  private static final class TestPrimitive {
    public TestPrimitive() {}
  }

  private static TestPrimitive getTestPrimitive(TestKey key) {
    return new TestPrimitive();
  }

  @Test
  public void test_primitiveConstructorCreate_works() throws Exception {
    PrimitiveConstructor<TestKey, TestPrimitive> unused = PrimitiveConstructor.create(
        PrimitiveConstructorTest::getTestPrimitive, TestKey.class, TestPrimitive.class);
  }

  @Test
  public void test_primitiveConstructorConstructPrimitive_works() throws Exception {
    PrimitiveConstructor<TestKey, TestPrimitive> primitiveConstructor = PrimitiveConstructor.create(
        PrimitiveConstructorTest::getTestPrimitive, TestKey.class, TestPrimitive.class);
    assertThat(primitiveConstructor.constructPrimitive(new TestKey())).isNotNull();
  }

  @Test
  public void test_primitiveConstructorGetKeyClass_works() throws Exception {
    PrimitiveConstructor<TestKey, TestPrimitive> primitiveConstructor = PrimitiveConstructor.create(
        PrimitiveConstructorTest::getTestPrimitive, TestKey.class, TestPrimitive.class);
    assertThat(primitiveConstructor.getKeyClass()).isEqualTo(TestKey.class);
  }

  @Test
  public void test_primitiveConstructorGetPrimitiveClass_works() throws Exception {
    PrimitiveConstructor<TestKey, TestPrimitive> primitiveConstructor = PrimitiveConstructor.create(
        PrimitiveConstructorTest::getTestPrimitive, TestKey.class, TestPrimitive.class);
    assertThat(primitiveConstructor.getPrimitiveClass()).isEqualTo(TestPrimitive.class);
  }
}
