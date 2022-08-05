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
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.TestProto;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
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

  // ================================================================================================
  // PARAMETERS TESTS
  // ================================================================================================
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

  @Test
  public void test_registerAllParametersSerializers_checkDispatch() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    registry.registerParametersSerializer(
        ParametersSerializer.create(
            MutableSerializationRegistryTest::serializeParameters1ToA,
            TestParameters1.class,
            TestSerializationA.class));
    registry.registerParametersSerializer(
        ParametersSerializer.create(
            MutableSerializationRegistryTest::serializeParameters1ToB,
            TestParameters1.class,
            TestSerializationB.class));
    registry.registerParametersSerializer(
        ParametersSerializer.create(
            MutableSerializationRegistryTest::serializeParameters2ToA,
            TestParameters2.class,
            TestSerializationA.class));
    registry.registerParametersSerializer(
        ParametersSerializer.create(
            MutableSerializationRegistryTest::serializeParameters2ToB,
            TestParameters2.class,
            TestSerializationB.class));
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
  public void test_registerAllParametersParsers_checkDispatch() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    registry.registerParametersParser(
        ParametersParser.create(
            MutableSerializationRegistryTest::parseAToParameters1, A_1, TestSerializationA.class));
    registry.registerParametersParser(
        ParametersParser.create(
            MutableSerializationRegistryTest::parseBToParameters1, B_1, TestSerializationB.class));
    registry.registerParametersParser(
        ParametersParser.create(
            MutableSerializationRegistryTest::parseAToParameters2, A_2, TestSerializationA.class));
    registry.registerParametersParser(
        ParametersParser.create(
            MutableSerializationRegistryTest::parseBToParameters2, B_2, TestSerializationB.class));
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
  public void test_parseParametersWithLegacyFallback_testFallback() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    ProtoParametersSerialization protoParameters =
        ProtoParametersSerialization.create(
            "typeUrlForTesting73107", OutputPrefixType.TINK, TestProto.getDefaultInstance());
    Parameters parameters = registry.parseParametersWithLegacyFallback(protoParameters);
    assertThat(parameters).isInstanceOf(LegacyProtoParameters.class);
    LegacyProtoParameters legacyProtoParameters = (LegacyProtoParameters) parameters;
    assertThat(legacyProtoParameters.getSerialization().getKeyTemplate().getTypeUrl())
        .isEqualTo("typeUrlForTesting73107");
  }

  private static TestParameters1 parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    return new TestParameters1();
  }

  @Test
  public void test_parseParametersWithLegacyFallback_testRegistered() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    registry.registerParametersParser(
        ParametersParser.create(
            MutableSerializationRegistryTest::parseParameters,
            Util.toBytesFromPrintableAscii("typeUrlForTesting98178"),
            ProtoParametersSerialization.class));
    ProtoParametersSerialization protoParameters =
        ProtoParametersSerialization.create(
            "typeUrlForTesting98178", OutputPrefixType.TINK, TestProto.getDefaultInstance());
    Parameters parameters = registry.parseParametersWithLegacyFallback(protoParameters);
    assertThat(parameters).isInstanceOf(TestParameters1.class);
  }

  @Test
  public void test_parseKeyWithLegacyFallback_testFallback() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    ProtoKeySerialization protoKey =
        ProtoKeySerialization.create(
            "typeUrlForTesting21125",
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    Key key = registry.parseKeyWithLegacyFallback(protoKey, InsecureSecretKeyAccess.get());
    assertThat(key).isInstanceOf(LegacyProtoKey.class);
    LegacyProtoKey legacyProtoKey = (LegacyProtoKey) key;
    assertThat(legacyProtoKey.getSerialization(InsecureSecretKeyAccess.get()).getTypeUrl())
        .isEqualTo("typeUrlForTesting21125");
  }

  private static TestKey1 parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return new TestKey1();
  }

  @Test
  public void test_parseKeyWithLegacyFallback_testRegistered() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    registry.registerKeyParser(
        KeyParser.create(
            MutableSerializationRegistryTest::parseKey,
            Util.toBytesFromPrintableAscii("typeUrlForTesting18412"),
            ProtoKeySerialization.class));
    ProtoKeySerialization protoKey =
        ProtoKeySerialization.create(
            "typeUrlForTesting18412",
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    Key key = registry.parseKeyWithLegacyFallback(protoKey, InsecureSecretKeyAccess.get());
    assertThat(key).isInstanceOf(TestKey1.class);
  }
}
