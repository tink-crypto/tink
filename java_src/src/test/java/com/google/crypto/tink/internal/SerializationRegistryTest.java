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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link SerializationRegistry}. */
@RunWith(JUnit4.class)
public final class SerializationRegistryTest {
  // ===============================================================================================
  // SETUP:
  // We create 2 different key classes (TestKey1, TestKey2) and two different serialization classes
  // (TestSerializationA, TestSerializationB), and provide ways to parse and serialize both keys
  // with both methods.
  //
  // For this, we provide the methods serializeKey{1,2}to{A,B} and parseKey{A,B}to{1,2}. The method
  // serializeKeyBto1 then uses the constant B_1 in the object identifier.
  //
  // Note that calling these multiple times will give different objects (which allows us to test
  // that registering different objects for the same task fails).
  //
  // We pick the object identifiers so that they are unique per serialization type, but *not*
  // unique globally (since different serialization types may use the same object identifiers for
  // different key types).
  // ===============================================================================================

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

  private static Key parseAToKey2(
      TestSerializationA serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!A_2.equals(serialization.getObjectIdentifier())) {
      throw new GeneralSecurityException("Wrong object identifier");
    }
    SecretKeyAccess.requireAccess(access);
    return new TestKey2();
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

  private static Key parseBToKey2(
      TestSerializationB serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!B_2.equals(serialization.getObjectIdentifier())) {
      throw new GeneralSecurityException("Wrong object identifier");
    }
    SecretKeyAccess.requireAccess(access);
    return new TestKey2();
  }

  // ======================================================================= Key serialization tests
  @Test
  public void test_registerSerializerAndGet() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeySerializer(
                KeySerializer.create(
                    SerializationRegistryTest::serializeKey1ToA,
                    TestKey1.class,
                    TestSerializationA.class))
            .build();
    assertThat(registry.serializeKey(new TestKey1(), TestSerializationA.class, ACCESS)).isNotNull();
  }

  @Test
  public void test_emptyRegistry_throws() throws Exception {
    SerializationRegistry registry = new SerializationRegistry.Builder().build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(new TestKey1(), TestSerializationA.class, ACCESS));
  }

  @Test
  public void test_noAccessSerializer_throws() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeySerializer(
                KeySerializer.create(
                    SerializationRegistryTest::serializeKey1ToA,
                    TestKey1.class,
                    TestSerializationA.class))
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(new TestKey1(), TestSerializationA.class, /* access= */ null));
  }

  @Test
  public void test_registerSameSerializerTwice_works() throws Exception {
    KeySerializer<TestKey1, TestSerializationA> testSerializer =
        KeySerializer.create(
            SerializationRegistryTest::serializeKey1ToA, TestKey1.class, TestSerializationA.class);
    new SerializationRegistry.Builder()
        .registerKeySerializer(testSerializer)
        .registerKeySerializer(testSerializer)
        .build();
  }

  @Test
  public void test_registerDifferentSerializerWithSameKeyType_throws() throws Exception {
    KeySerializer<TestKey1, TestSerializationA> testSerializer1 =
        KeySerializer.create(
            SerializationRegistryTest::serializeKey1ToA, TestKey1.class, TestSerializationA.class);
    KeySerializer<TestKey1, TestSerializationA> testSerializer2 =
        KeySerializer.create(
            SerializationRegistryTest::serializeKey1ToA, TestKey1.class, TestSerializationA.class);
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder();
    builder.registerKeySerializer(testSerializer1);
    assertThrows(
        GeneralSecurityException.class,
        () -> builder.registerKeySerializer(testSerializer2).build());
  }

  @Test
  public void test_registerDifferentSerializerWithDifferentKeyType_works() throws Exception {
    KeySerializer<TestKey1, TestSerializationA> testSerializer1 =
        KeySerializer.create(
            SerializationRegistryTest::serializeKey1ToA, TestKey1.class, TestSerializationA.class);
    KeySerializer<TestKey2, TestSerializationA> testSerializer2 =
        KeySerializer.create(
            SerializationRegistryTest::serializeKey2ToA, TestKey2.class, TestSerializationA.class);
    new SerializationRegistry.Builder()
        .registerKeySerializer(testSerializer1)
        .registerKeySerializer(testSerializer2)
        .build();
  }

  @Test
  public void test_registerDifferentSerializerWithDifferentSerializationType_works()
      throws Exception {
    KeySerializer<TestKey1, TestSerializationA> testSerializer1 =
        KeySerializer.create(
            SerializationRegistryTest::serializeKey1ToA, TestKey1.class, TestSerializationA.class);
    KeySerializer<TestKey2, TestSerializationA> testSerializer2 =
        KeySerializer.create(
            SerializationRegistryTest::serializeKey2ToA, TestKey2.class, TestSerializationA.class);
    new SerializationRegistry.Builder()
        .registerKeySerializer(testSerializer1)
        .registerKeySerializer(testSerializer2)
        .build();
  }

  @Test
  public void test_registerAll_checkDispatch() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeySerializer(
                KeySerializer.create(
                    SerializationRegistryTest::serializeKey1ToA,
                    TestKey1.class,
                    TestSerializationA.class))
            .registerKeySerializer(
                KeySerializer.create(
                    SerializationRegistryTest::serializeKey1ToB,
                    TestKey1.class,
                    TestSerializationB.class))
            .registerKeySerializer(
                KeySerializer.create(
                    SerializationRegistryTest::serializeKey2ToA,
                    TestKey2.class,
                    TestSerializationA.class))
            .registerKeySerializer(
                KeySerializer.create(
                    SerializationRegistryTest::serializeKey2ToB,
                    TestKey2.class,
                    TestSerializationB.class))
            .build();
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
  public void test_serializer_copyWorks() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeySerializer(
                KeySerializer.create(
                    SerializationRegistryTest::serializeKey1ToA,
                    TestKey1.class,
                    TestSerializationA.class))
            .build();
    SerializationRegistry registry2 = new SerializationRegistry.Builder(registry).build();
    assertThat(registry2.serializeKey(new TestKey1(), TestSerializationA.class, ACCESS))
        .isNotNull();
  }

  @Test
  public void test_copyDoesNotChangeOldVersion_serializer() throws Exception {
    SerializationRegistry registry1 = new SerializationRegistry.Builder().build();
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder(registry1);
    SerializationRegistry registry2 = builder.build();
    builder.registerKeySerializer(
        KeySerializer.create(
            SerializationRegistryTest::serializeKey1ToA, TestKey1.class, TestSerializationA.class));
    assertThrows(
        GeneralSecurityException.class,
        () -> registry1.serializeKey(new TestKey1(), TestSerializationA.class, ACCESS));
    assertThrows(
        GeneralSecurityException.class,
        () -> registry2.serializeKey(new TestKey1(), TestSerializationA.class, ACCESS));
  }

  // ============================================================================= Key parsing tests
  @Test
  public void test_registerParserAndGet() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeyParser(
                KeyParser.create(
                    SerializationRegistryTest::parseAToKey1, A_1, TestSerializationA.class))
            .build();
    assertThat(registry.parseKey(new TestSerializationA(A_1), ACCESS)).isNotNull();
  }

  @Test
  public void test_registerParser_noAccess_throws() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeyParser(
                KeyParser.create(
                    SerializationRegistryTest::parseAToKey1, A_1, TestSerializationA.class))
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(new TestSerializationA(A_1), /* access = */ null));
  }

  @Test
  public void test_parse_emptyRegistry_throws() throws Exception {
    SerializationRegistry registry = new SerializationRegistry.Builder().build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(new TestSerializationA(A_1), ACCESS));
  }

  @Test
  public void test_registerSameParserTwice_works() throws Exception {
    KeyParser<TestSerializationA> testParser =
        KeyParser.create(SerializationRegistryTest::parseAToKey1, A_1, TestSerializationA.class);
    new SerializationRegistry.Builder()
        .registerKeyParser(testParser)
        .registerKeyParser(testParser)
        .build();
  }

  @Test
  public void test_registerDifferentParsersWithSameKeyType_throws() throws Exception {
    KeyParser<TestSerializationA> testParser1 =
        KeyParser.create(SerializationRegistryTest::parseAToKey1, A_1, TestSerializationA.class);
    KeyParser<TestSerializationA> testParser2 =
        KeyParser.create(SerializationRegistryTest::parseAToKey1, A_1, TestSerializationA.class);
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder();
    builder.registerKeyParser(testParser1);
    assertThrows(
        GeneralSecurityException.class, () -> builder.registerKeyParser(testParser2).build());
  }

  @Test
  public void test_registerDifferentParsersWithDifferentSerializationType_works() throws Exception {
    KeyParser<TestSerializationA> testParser1 =
        KeyParser.create(SerializationRegistryTest::parseAToKey1, A_1, TestSerializationA.class);
    KeyParser<TestSerializationB> testParser2 =
        KeyParser.create(SerializationRegistryTest::parseBToKey1, B_1, TestSerializationB.class);
    new SerializationRegistry.Builder()
        .registerKeyParser(testParser1)
        .registerKeyParser(testParser2)
        .build();
  }

  @Test
  public void test_registerDifferentParsersWithDifferentKeyType_works() throws Exception {
    KeyParser<TestSerializationA> testParser1 =
        KeyParser.create(SerializationRegistryTest::parseAToKey1, A_1, TestSerializationA.class);
    KeyParser<TestSerializationA> testParser2 =
        KeyParser.create(SerializationRegistryTest::parseAToKey2, A_2, TestSerializationA.class);
    new SerializationRegistry.Builder()
        .registerKeyParser(testParser1)
        .registerKeyParser(testParser2)
        .build();
  }

  @Test
  public void test_registerAllParsers_checkDispatch() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeyParser(
                KeyParser.create(
                    SerializationRegistryTest::parseAToKey1, A_1, TestSerializationA.class))
            .registerKeyParser(
                KeyParser.create(
                    SerializationRegistryTest::parseBToKey1, B_1, TestSerializationB.class))
            .registerKeyParser(
                KeyParser.create(
                    SerializationRegistryTest::parseAToKey2, A_2, TestSerializationA.class))
            .registerKeyParser(
                KeyParser.create(
                    SerializationRegistryTest::parseBToKey2, B_2, TestSerializationB.class))
            .build();
    assertThat(registry.parseKey(new TestSerializationA(A_1), ACCESS)).isInstanceOf(TestKey1.class);
    assertThat(registry.parseKey(new TestSerializationA(A_2), ACCESS)).isInstanceOf(TestKey2.class);
    assertThat(registry.parseKey(new TestSerializationB(B_1), ACCESS)).isInstanceOf(TestKey1.class);
    assertThat(registry.parseKey(new TestSerializationB(B_2), ACCESS)).isInstanceOf(TestKey2.class);
  }

  @Test
  public void test_copyWorksForParsers() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeyParser(
                KeyParser.create(
                    SerializationRegistryTest::parseAToKey1, A_1, TestSerializationA.class))
            .build();
    SerializationRegistry registry2 = new SerializationRegistry.Builder(registry).build();
    assertThat(registry2.parseKey(new TestSerializationA(A_1), ACCESS)).isNotNull();
  }

  @Test
  public void test_copyDoesNotChangeOldVersion_parser() throws Exception {
    SerializationRegistry registry1 = new SerializationRegistry.Builder().build();
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder(registry1);
    SerializationRegistry registry2 = builder.build();

    builder
        .registerKeyParser(
            KeyParser.create(
                SerializationRegistryTest::parseAToKey1, A_1, TestSerializationA.class))
        .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry1.parseKey(new TestSerializationA(A_1), ACCESS));
    assertThrows(
        GeneralSecurityException.class,
        () -> registry2.parseKey(new TestSerializationA(A_1), ACCESS));
  }

  // ================================================================================================
  // PARAMETERS TESTS
  // ================================================================================================
  private static TestSerializationA serializeParameters1ToA(TestParameters1 keyFormat)
      throws GeneralSecurityException {
    return new TestSerializationA(A_1);
  }

  private static TestSerializationA serializeParameters2ToA(TestParameters2 keyFormat)
      throws GeneralSecurityException {
    return new TestSerializationA(A_2);
  }

  private static TestSerializationB serializeParameters1ToB(TestParameters1 keyFormat)
      throws GeneralSecurityException {
    return new TestSerializationB(B_1);
  }

  private static TestSerializationB serializeParameters2ToB(TestParameters2 keyFormat)
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

  private static Parameters parseAToParameters2(TestSerializationA serialization)
      throws GeneralSecurityException {
    if (!A_2.equals(serialization.getObjectIdentifier())) {
      throw new GeneralSecurityException("Wrong object identifier");
    }
    return new TestParameters2();
  }

  private static Parameters parseBToParameters1(TestSerializationB serialization)
      throws GeneralSecurityException {
    if (!B_1.equals(serialization.getObjectIdentifier())) {
      throw new GeneralSecurityException("Wrong object identifier");
    }
    return new TestParameters1();
  }

  private static Parameters parseBToParameters2(TestSerializationB serialization)
      throws GeneralSecurityException {
    if (!B_2.equals(serialization.getObjectIdentifier())) {
      throw new GeneralSecurityException("Wrong object identifier");
    }
    return new TestParameters2();
  }

  // ParametersSerialization tests
  @Test
  public void test_registerParametersSerializerAndGet() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerParametersSerializer(
                ParametersSerializer.create(
                    SerializationRegistryTest::serializeParameters1ToA,
                    TestParameters1.class,
                    TestSerializationA.class))
            .build();
    assertThat(registry.serializeParameters(new TestParameters1(), TestSerializationA.class))
        .isNotNull();
  }

  @Test
  public void test_emptyRegistrySerializeParameters_throws() throws Exception {
    SerializationRegistry registry = new SerializationRegistry.Builder().build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeParameters(new TestParameters1(), TestSerializationA.class));
  }

  @Test
  public void test_registerSameFormatSerializerTwice_works() throws Exception {
    ParametersSerializer<TestParameters1, TestSerializationA> testSerializer =
        ParametersSerializer.create(
            SerializationRegistryTest::serializeParameters1ToA,
            TestParameters1.class,
            TestSerializationA.class);
    new SerializationRegistry.Builder()
        .registerParametersSerializer(testSerializer)
        .registerParametersSerializer(testSerializer)
        .build();
  }

  @Test
  public void test_registerDifferentSerializerWithSameFormatType_throws() throws Exception {
    ParametersSerializer<TestParameters1, TestSerializationA> testSerializer1 =
        ParametersSerializer.create(
            SerializationRegistryTest::serializeParameters1ToA,
            TestParameters1.class,
            TestSerializationA.class);
    ParametersSerializer<TestParameters1, TestSerializationA> testSerializer2 =
        ParametersSerializer.create(
            SerializationRegistryTest::serializeParameters1ToA,
            TestParameters1.class,
            TestSerializationA.class);
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder();
    builder.registerParametersSerializer(testSerializer1);
    assertThrows(
        GeneralSecurityException.class,
        () -> builder.registerParametersSerializer(testSerializer2).build());
  }

  @Test
  public void test_registerDifferentSerializerWithDifferentFormatType_works() throws Exception {
    ParametersSerializer<TestParameters1, TestSerializationA> testSerializer1 =
        ParametersSerializer.create(
            SerializationRegistryTest::serializeParameters1ToA,
            TestParameters1.class,
            TestSerializationA.class);
    ParametersSerializer<TestParameters2, TestSerializationA> testSerializer2 =
        ParametersSerializer.create(
            SerializationRegistryTest::serializeParameters2ToA,
            TestParameters2.class,
            TestSerializationA.class);
    new SerializationRegistry.Builder()
        .registerParametersSerializer(testSerializer1)
        .registerParametersSerializer(testSerializer2)
        .build();
  }

  @Test
  public void test_registerDifferentSerializerWithDifferentFormatSerializationType_works()
      throws Exception {
    ParametersSerializer<TestParameters1, TestSerializationA> testSerializer1 =
        ParametersSerializer.create(
            SerializationRegistryTest::serializeParameters1ToA,
            TestParameters1.class,
            TestSerializationA.class);
    ParametersSerializer<TestParameters2, TestSerializationA> testSerializer2 =
        ParametersSerializer.create(
            SerializationRegistryTest::serializeParameters2ToA,
            TestParameters2.class,
            TestSerializationA.class);
    new SerializationRegistry.Builder()
        .registerParametersSerializer(testSerializer1)
        .registerParametersSerializer(testSerializer2)
        .build();
  }

  @Test
  public void test_registerAllFormatSerializers_checkDispatch() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerParametersSerializer(
                ParametersSerializer.create(
                    SerializationRegistryTest::serializeParameters1ToA,
                    TestParameters1.class,
                    TestSerializationA.class))
            .registerParametersSerializer(
                ParametersSerializer.create(
                    SerializationRegistryTest::serializeParameters1ToB,
                    TestParameters1.class,
                    TestSerializationB.class))
            .registerParametersSerializer(
                ParametersSerializer.create(
                    SerializationRegistryTest::serializeParameters2ToA,
                    TestParameters2.class,
                    TestSerializationA.class))
            .registerParametersSerializer(
                ParametersSerializer.create(
                    SerializationRegistryTest::serializeParameters2ToB,
                    TestParameters2.class,
                    TestSerializationB.class))
            .build();
    assertThat(
            registry
                .serializeParameters(new TestParameters1(), TestSerializationA.class)
                .getObjectIdentifier())
        .isEqualTo(A_1);
    assertThat(
            registry
                .serializeParameters(new TestParameters2(), TestSerializationA.class)
                .getObjectIdentifier())
        .isEqualTo(A_2);
    assertThat(
            registry
                .serializeParameters(new TestParameters1(), TestSerializationB.class)
                .getObjectIdentifier())
        .isEqualTo(B_1);
    assertThat(
            registry
                .serializeParameters(new TestParameters2(), TestSerializationB.class)
                .getObjectIdentifier())
        .isEqualTo(B_2);
  }

  @Test
  public void test_formatSerializer_copyWorks() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerParametersSerializer(
                ParametersSerializer.create(
                    SerializationRegistryTest::serializeParameters1ToA,
                    TestParameters1.class,
                    TestSerializationA.class))
            .build();
    SerializationRegistry registry2 = new SerializationRegistry.Builder(registry).build();
    assertThat(registry2.serializeParameters(new TestParameters1(), TestSerializationA.class))
        .isNotNull();
  }

  @Test
  public void test_copyDoesNotChangeOldVersion_formatSerializer() throws Exception {
    SerializationRegistry registry1 = new SerializationRegistry.Builder().build();
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder(registry1);
    SerializationRegistry registry2 = builder.build();
    builder.registerParametersSerializer(
        ParametersSerializer.create(
            SerializationRegistryTest::serializeParameters1ToA,
            TestParameters1.class,
            TestSerializationA.class));
    assertThrows(
        GeneralSecurityException.class,
        () -> registry1.serializeParameters(new TestParameters1(), TestSerializationA.class));
    assertThrows(
        GeneralSecurityException.class,
        () -> registry2.serializeParameters(new TestParameters1(), TestSerializationA.class));
  }

  // ========================================================================Parameters parsing
  // tests
  @Test
  public void test_registerFormatParserAndGet() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerKeyParser(
                KeyParser.create(
                    SerializationRegistryTest::parseAToKey1, A_1, TestSerializationA.class))
            .build();
    assertThat(registry.parseKey(new TestSerializationA(A_1), ACCESS)).isNotNull();
  }

  @Test
  public void test_formatParse_emptyRegistry_throws() throws Exception {
    SerializationRegistry registry = new SerializationRegistry.Builder().build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseParameters(new TestSerializationA(A_1)));
  }

  @Test
  public void test_registerSameFormatParserTwice_works() throws Exception {
    ParametersParser<TestSerializationA> testParser =
        ParametersParser.create(
            SerializationRegistryTest::parseAToParameters1, A_1, TestSerializationA.class);
    new SerializationRegistry.Builder()
        .registerParametersParser(testParser)
        .registerParametersParser(testParser)
        .build();
  }

  @Test
  public void test_registerDifferentParsersWithSameParametersType_throws() throws Exception {
    ParametersParser<TestSerializationA> testParser1 =
        ParametersParser.create(
            SerializationRegistryTest::parseAToParameters1, A_1, TestSerializationA.class);
    ParametersParser<TestSerializationA> testParser2 =
        ParametersParser.create(
            SerializationRegistryTest::parseAToParameters1, A_1, TestSerializationA.class);
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder();
    builder.registerParametersParser(testParser1);
    assertThrows(
        GeneralSecurityException.class,
        () -> builder.registerParametersParser(testParser2).build());
  }

  @Test
  public void test_registerDifferentFormatParsersWithDifferentSerializationType_works()
      throws Exception {
    ParametersParser<TestSerializationA> testParser1 =
        ParametersParser.create(
            SerializationRegistryTest::parseAToParameters1, A_1, TestSerializationA.class);
    ParametersParser<TestSerializationB> testParser2 =
        ParametersParser.create(
            SerializationRegistryTest::parseBToParameters1, B_1, TestSerializationB.class);
    new SerializationRegistry.Builder()
        .registerParametersParser(testParser1)
        .registerParametersParser(testParser2)
        .build();
  }

  @Test
  public void test_registerDifferentFormatParsersWithDifferentKeyType_works() throws Exception {
    ParametersParser<TestSerializationA> testParser1 =
        ParametersParser.create(
            SerializationRegistryTest::parseAToParameters1, A_1, TestSerializationA.class);
    ParametersParser<TestSerializationA> testParser2 =
        ParametersParser.create(
            SerializationRegistryTest::parseAToParameters2, A_2, TestSerializationA.class);
    new SerializationRegistry.Builder()
        .registerParametersParser(testParser1)
        .registerParametersParser(testParser2)
        .build();
  }

  @Test
  public void test_registerAllFormatParsers_checkDispatch() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerParametersParser(
                ParametersParser.create(
                    SerializationRegistryTest::parseAToParameters1, A_1, TestSerializationA.class))
            .registerParametersParser(
                ParametersParser.create(
                    SerializationRegistryTest::parseBToParameters1, B_1, TestSerializationB.class))
            .registerParametersParser(
                ParametersParser.create(
                    SerializationRegistryTest::parseAToParameters2, A_2, TestSerializationA.class))
            .registerParametersParser(
                ParametersParser.create(
                    SerializationRegistryTest::parseBToParameters2, B_2, TestSerializationB.class))
            .build();
    assertThat(registry.parseParameters(new TestSerializationA(A_1)))
        .isInstanceOf(TestParameters1.class);
    assertThat(registry.parseParameters(new TestSerializationA(A_2)))
        .isInstanceOf(TestParameters2.class);
    assertThat(registry.parseParameters(new TestSerializationB(B_1)))
        .isInstanceOf(TestParameters1.class);
    assertThat(registry.parseParameters(new TestSerializationB(B_2)))
        .isInstanceOf(TestParameters2.class);
  }

  @Test
  public void test_copyWorksForFormatParsers() throws Exception {
    SerializationRegistry registry =
        new SerializationRegistry.Builder()
            .registerParametersParser(
                ParametersParser.create(
                    SerializationRegistryTest::parseAToParameters1, A_1, TestSerializationA.class))
            .build();
    SerializationRegistry registry2 = new SerializationRegistry.Builder(registry).build();
    assertThat(registry2.parseParameters(new TestSerializationA(A_1))).isNotNull();
  }

  @Test
  public void test_copyDoesNotChangeOldVersion_formatParser() throws Exception {
    SerializationRegistry registry1 = new SerializationRegistry.Builder().build();
    SerializationRegistry.Builder builder = new SerializationRegistry.Builder(registry1);
    SerializationRegistry registry2 = builder.build();

    builder
        .registerParametersParser(
            ParametersParser.create(
                SerializationRegistryTest::parseAToParameters1, A_1, TestSerializationA.class))
        .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry1.parseParameters(new TestSerializationA(A_1)));
    assertThrows(
        GeneralSecurityException.class,
        () -> registry2.parseParameters(new TestSerializationA(A_1)));
  }
}
