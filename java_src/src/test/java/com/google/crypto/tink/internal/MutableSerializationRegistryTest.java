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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyFormat;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Thread safety tests for {@link MutableSerializationRegistry}.
 *
 * <p>We repeat the main tests in SerializationRegistryTest. There really shouldn't be both classes,
 * but currently this is what we need, and the other is what we should have.
 */
@RunWith(JUnit4.class)
public final class MutableSerializationRegistryTest {
  private static final Optional<SecretKeyAccess> ACCESS =
      Optional.of(InsecureSecretKeyAccess.get());

  private static final Bytes A_1 = Bytes.copyFrom("0".getBytes(UTF_8));
  private static final Bytes A_2 = Bytes.copyFrom("1".getBytes(UTF_8));
  private static final Bytes B_1 = Bytes.copyFrom("1".getBytes(UTF_8));
  private static final Bytes B_2 = Bytes.copyFrom("2".getBytes(UTF_8));

  @Immutable
  private static final class TestKey1 extends Key {
    @Override
    public KeyFormat getKeyFormat() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    public Optional<Integer> getIdRequirement() {
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
    public KeyFormat getKeyFormat() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    public Optional<Integer> getIdRequirement() {
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

  private static TestSerializationA serializeKey1ToA(TestKey1 key, Optional<SecretKeyAccess> access)
      throws GeneralSecurityException {
    SecretKeyAccess.requireAccess(access);
    return new TestSerializationA(A_1);
  }

  private static TestSerializationA serializeKey2ToA(TestKey2 key, Optional<SecretKeyAccess> access)
      throws GeneralSecurityException {
    SecretKeyAccess.requireAccess(access);
    return new TestSerializationA(A_2);
  }

  private static TestSerializationB serializeKey1ToB(TestKey1 key, Optional<SecretKeyAccess> access)
      throws GeneralSecurityException {
    SecretKeyAccess.requireAccess(access);
    return new TestSerializationB(B_1);
  }

  private static TestSerializationB serializeKey2ToB(TestKey2 key, Optional<SecretKeyAccess> access)
      throws GeneralSecurityException {
    SecretKeyAccess.requireAccess(access);
    return new TestSerializationB(B_2);
  }

  private static Key parseAToKey1(
      TestSerializationA serialization, Optional<SecretKeyAccess> access)
      throws GeneralSecurityException {
    if (!A_1.equals(serialization.getObjectIdentifier())) {
      throw new GeneralSecurityException("Wrong object identifier");
    }
    SecretKeyAccess.requireAccess(access);
    return new TestKey1();
  }

  private static Key parseAToKey2(
      TestSerializationA serialization, Optional<SecretKeyAccess> access)
      throws GeneralSecurityException {
    if (!A_2.equals(serialization.getObjectIdentifier())) {
      throw new GeneralSecurityException("Wrong object identifier");
    }
    SecretKeyAccess.requireAccess(access);
    return new TestKey2();
  }

  private static Key parseBToKey1(
      TestSerializationB serialization, Optional<SecretKeyAccess> access)
      throws GeneralSecurityException {
    if (!B_1.equals(serialization.getObjectIdentifier())) {
      throw new GeneralSecurityException("Wrong object identifier");
    }
    SecretKeyAccess.requireAccess(access);
    return new TestKey1();
  }

  private static Key parseBToKey2(
      TestSerializationB serialization, Optional<SecretKeyAccess> access)
      throws GeneralSecurityException {
    if (!B_2.equals(serialization.getObjectIdentifier())) {
      throw new GeneralSecurityException("Wrong object identifier");
    }
    SecretKeyAccess.requireAccess(access);
    return new TestKey2();
  }

  // ======================================================================= Key serialization tests
  @Test
  public void test_registerAllSerializers_checkDispatch() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    registry.registerKeySerializer(
        KeySerializer.create(
            MutableSerializationRegistryTest::serializeKey1ToA,
            TestKey1.class,
            TestSerializationA.class));
    registry.registerKeySerializer(
        KeySerializer.create(
            MutableSerializationRegistryTest::serializeKey1ToB,
            TestKey1.class,
            TestSerializationB.class));
    registry.registerKeySerializer(
        KeySerializer.create(
            MutableSerializationRegistryTest::serializeKey2ToA,
            TestKey2.class,
            TestSerializationA.class));
    registry.registerKeySerializer(
        KeySerializer.create(
            MutableSerializationRegistryTest::serializeKey2ToB,
            TestKey2.class,
            TestSerializationB.class));
    assertThat(
            registry
                .serializeKey(new TestKey1(), TestSerializationA.class, ACCESS)
                .getObjectIdentifier())
        .isEqualTo(A_1);
    assertThat(
            registry
                .serializeKey(new TestKey2(), TestSerializationA.class, ACCESS)
                .getObjectIdentifier())
        .isEqualTo(A_2);
    assertThat(
            registry
                .serializeKey(new TestKey1(), TestSerializationB.class, ACCESS)
                .getObjectIdentifier())
        .isEqualTo(B_1);
    assertThat(
            registry
                .serializeKey(new TestKey2(), TestSerializationB.class, ACCESS)
                .getObjectIdentifier())
        .isEqualTo(B_2);
  }

  @Test
  public void test_registerAllParsers_checkDispatch() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    registry.registerKeyParser(
        KeyParser.create(
            MutableSerializationRegistryTest::parseAToKey1, A_1, TestSerializationA.class));
    registry.registerKeyParser(
        KeyParser.create(
            MutableSerializationRegistryTest::parseBToKey1, B_1, TestSerializationB.class));
    registry.registerKeyParser(
        KeyParser.create(
            MutableSerializationRegistryTest::parseAToKey2, A_2, TestSerializationA.class));
    registry.registerKeyParser(
        KeyParser.create(
            MutableSerializationRegistryTest::parseBToKey2, B_2, TestSerializationB.class));
    assertThat(registry.parseKey(new TestSerializationA(A_1), ACCESS)).isInstanceOf(TestKey1.class);
    assertThat(registry.parseKey(new TestSerializationA(A_2), ACCESS)).isInstanceOf(TestKey2.class);
    assertThat(registry.parseKey(new TestSerializationB(B_1), ACCESS)).isInstanceOf(TestKey1.class);
    assertThat(registry.parseKey(new TestSerializationB(B_2), ACCESS)).isInstanceOf(TestKey2.class);
  }
}
