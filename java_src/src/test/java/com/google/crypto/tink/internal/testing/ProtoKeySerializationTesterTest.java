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

package com.google.crypto.tink.internal.testing;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.TestProto;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ProtoKeySerializationTesterTest {
  private static final String TYPE_URL = "my_type_url";
  private static final Bytes TYPE_URL_BYTES = Bytes.copyFrom(TYPE_URL.getBytes(US_ASCII));

  private static MutableSerializationRegistry registry;

  /** If true, the test parsing/serialization functions will require secret key access. */
  private static boolean globalRequireSecretKeyAccessOnParsingAndSerializing = false;

  @Before
  public void resetSecretKeyAccess() {
    globalRequireSecretKeyAccessOnParsingAndSerializing = false;
  }

  private static class TestKey extends Key {
    private final ByteString strOfLength4;
    private final OutputPrefixType outputPrefixType;
    private final KeyMaterialType keyMaterialType;
    @Nullable private final Integer idRequirement;

    public TestKey(
        ByteString strOfLength4,
        OutputPrefixType outputPrefixType,
        KeyMaterialType keyMaterialType,
        @Nullable Integer idRequirement)
        throws GeneralSecurityException {
      if (strOfLength4.size() != 4) {
        throw new GeneralSecurityException("Str has to have length 4");
      }
      this.strOfLength4 = strOfLength4;
      this.outputPrefixType = outputPrefixType;
      this.keyMaterialType = keyMaterialType;
      this.idRequirement = idRequirement;
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
      return idRequirement;
    }

    /** Returns a string of length exactly 4. */
    public ByteString getStr() {
      return strOfLength4;
    }

    public OutputPrefixType getOutputPrefixType() {
      return outputPrefixType;
    }

    public KeyMaterialType getKeyMaterialType() {
      return keyMaterialType;
    }

    @Override
    public boolean equalsKey(Key k) {
      if (!(k instanceof TestKey)) {
        return false;
      }
      TestKey other = (TestKey) k;
      return strOfLength4.equals(other.strOfLength4)
          && outputPrefixType.equals(other.outputPrefixType)
          && keyMaterialType.equals(other.keyMaterialType)
          && Objects.equals(idRequirement, other.idRequirement);
    }

    @Override
    public Parameters getParameters() {
      throw new UnsupportedOperationException("Not needed for serialization testing");
    }
  }

  private static ProtoKeySerialization serializeKey(TestKey key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (globalRequireSecretKeyAccessOnParsingAndSerializing) {
      SecretKeyAccess.requireAccess(access);
    }
    return ProtoKeySerialization.create(
        TYPE_URL,
        TestProto.newBuilder().setStr(key.getStr()).build().toByteString(),
        key.getKeyMaterialType(),
        key.getOutputPrefixType(),
        key.getIdRequirementOrNull());
  }

  private static TestKey parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException("Wrong type URL");
    }
    if (globalRequireSecretKeyAccessOnParsingAndSerializing) {
      SecretKeyAccess.requireAccess(access);
    }
    try {
      TestProto proto =
          TestProto.parseFrom(serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      return new TestKey(
          proto.getStr(),
          serialization.getOutputPrefixType(),
          serialization.getKeyMaterialType(),
          serialization.getIdRequirementOrNull());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing failed: ", e);
    }
  }

  @BeforeClass
  public static void registerSerializerAndParser() throws Exception {
    registry = new MutableSerializationRegistry();
    registry.registerKeyParser(
        KeyParser.create(
            ProtoKeySerializationTesterTest::parseKey,
            TYPE_URL_BYTES,
            ProtoKeySerialization.class));
    registry.registerKeySerializer(
        KeySerializer.create(
            ProtoKeySerializationTesterTest::serializeKey,
            TestKey.class,
            ProtoKeySerialization.class));
  }

  @Test
  public void testParseAndSerialize_testerWorksIfCorrect() throws Exception {
    ByteString s = ByteString.copyFrom(new byte[] {1, 2, 3, 4});
    TestKey key =
        new TestKey(s, OutputPrefixType.TINK, KeyMaterialType.SYMMETRIC, /* idRequirement= */ 1357);
    TestProto proto = TestProto.newBuilder().setStr(s).build();

    ProtoKeySerializationTester tester =
        new ProtoKeySerializationTester(
            TYPE_URL, KeyMaterialType.SYMMETRIC, /* requiresSecretKeyAccess = */ false, registry);
    tester.testParse(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357);
    tester.testSerialize(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357);
    tester.testParseAndSerialize(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357);
  }

  // Same test as above, but with idRequirement == null
  @Test
  public void testParseAndSerialize_testerWorksIfCorrect_nullIdRequirement() throws Exception {
    ByteString s = ByteString.copyFrom(new byte[] {1, 2, 3, 4});
    TestKey key =
        new TestKey(s, OutputPrefixType.RAW, KeyMaterialType.SYMMETRIC, /* idRequirement= */ null);
    TestProto proto = TestProto.newBuilder().setStr(s).build();

    ProtoKeySerializationTester tester =
        new ProtoKeySerializationTester(
            TYPE_URL, KeyMaterialType.SYMMETRIC, /* requiresSecretKeyAccess = */ false, registry);
    tester.testParse(key, proto, OutputPrefixType.RAW, /* idRequirement= */ null);
    tester.testSerialize(key, proto, OutputPrefixType.RAW, /* idRequirement= */ null);
    tester.testParseAndSerialize(key, proto, OutputPrefixType.RAW, /* idRequirement= */ null);
  }

  @Test
  public void testParseAndSerialize_wrongKeyMaterialType_throws() throws Exception {
    ByteString s = ByteString.copyFrom(new byte[] {1, 2, 3, 4});
    TestKey key =
        new TestKey(
            s,
            OutputPrefixType.TINK,
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            /* idRequirement= */ 1357);
    TestProto proto = TestProto.newBuilder().setStr(s).build();

    ProtoKeySerializationTester tester =
        new ProtoKeySerializationTester(
            TYPE_URL, KeyMaterialType.SYMMETRIC, /* requiresSecretKeyAccess = */ false, registry);
    assertThrows(
        AssertionError.class,
        () -> tester.testParse(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357));
    assertThrows(
        AssertionError.class,
        () -> tester.testSerialize(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357));
    assertThrows(
        AssertionError.class,
        () ->
            tester.testParseAndSerialize(
                key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357));
  }

  @Test
  public void testParseAndSerialize_wrongValue_throws() throws Exception {
    TestKey key =
        new TestKey(
            ByteString.copyFrom(new byte[] {1, 2, 3, 4}),
            OutputPrefixType.TINK,
            KeyMaterialType.SYMMETRIC,
            /* idRequirement= */ 1357);
    TestProto proto =
        TestProto.newBuilder().setStr(ByteString.copyFrom(new byte[] {2, 3, 4, 5})).build();

    ProtoKeySerializationTester tester =
        new ProtoKeySerializationTester(
            TYPE_URL, KeyMaterialType.SYMMETRIC, /* requiresSecretKeyAccess = */ false, registry);
    assertThrows(
        AssertionError.class,
        () -> tester.testParse(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357));
    assertThrows(
        AssertionError.class,
        () -> tester.testSerialize(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357));
    assertThrows(
        AssertionError.class,
        () ->
            tester.testParseAndSerialize(
                key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357));
  }

  @Test
  public void testParseAndSerialize_testWrongIdRequirement_throws() throws Exception {
    ByteString s = ByteString.copyFrom(new byte[] {1, 2, 3, 4});
    TestKey key =
        new TestKey(s, OutputPrefixType.TINK, KeyMaterialType.SYMMETRIC, /* idRequirement= */ 1357);
    TestProto proto = TestProto.newBuilder().setStr(s).build();

    ProtoKeySerializationTester tester =
        new ProtoKeySerializationTester(
            TYPE_URL, KeyMaterialType.SYMMETRIC, /* requiresSecretKeyAccess = */ false, registry);
    assertThrows(
        AssertionError.class,
        () -> tester.testParse(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 567));
    assertThrows(
        AssertionError.class,
        () -> tester.testSerialize(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 567));
    assertThrows(
        AssertionError.class,
        () ->
            tester.testParseAndSerialize(
                key, proto, OutputPrefixType.TINK, /* idRequirement= */ 567));
  }

  @Test
  public void testParseAndSerialize_shouldRequireSecretKeyAccess_throws() throws Exception {
    ByteString s = ByteString.copyFrom(new byte[] {1, 2, 3, 4});
    TestKey key =
        new TestKey(s, OutputPrefixType.TINK, KeyMaterialType.SYMMETRIC, /* idRequirement= */ 1357);
    TestProto proto = TestProto.newBuilder().setStr(s).build();

    // We tell the tester that we require secret key access
    ProtoKeySerializationTester tester =
        new ProtoKeySerializationTester(
            TYPE_URL, KeyMaterialType.SYMMETRIC, /* requiresSecretKeyAccess = */ true, registry);
    assertThrows(
        AssertionError.class,
        () -> tester.testParse(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357));
    assertThrows(
        AssertionError.class,
        () -> tester.testSerialize(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357));
    assertThrows(
        AssertionError.class,
        () ->
            tester.testParseAndSerialize(
                key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357));
  }

  @Test
  public void testParseAndSerialize_doesRequireSecretKeyAccess_works() throws Exception {
    globalRequireSecretKeyAccessOnParsingAndSerializing = true;
    ByteString s = ByteString.copyFrom(new byte[] {1, 2, 3, 4});
    TestKey key =
        new TestKey(s, OutputPrefixType.TINK, KeyMaterialType.SYMMETRIC, /* idRequirement= */ 1357);
    TestProto proto = TestProto.newBuilder().setStr(s).build();

    // We tell the tester that we require secret key access
    ProtoKeySerializationTester tester =
        new ProtoKeySerializationTester(
            TYPE_URL, KeyMaterialType.SYMMETRIC, /* requiresSecretKeyAccess = */ true, registry);
    tester.testParse(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357);
    tester.testSerialize(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357);
    tester.testParseAndSerialize(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357);
  }

  @Test
  public void testParseAndSerialize_functionsRequireAccessButTesterDoesNot_throws()
      throws Exception {
    globalRequireSecretKeyAccessOnParsingAndSerializing = true;
    ByteString s = ByteString.copyFrom(new byte[] {1, 2, 3, 4});
    TestKey key =
        new TestKey(s, OutputPrefixType.TINK, KeyMaterialType.SYMMETRIC, /* idRequirement= */ 1357);
    TestProto proto = TestProto.newBuilder().setStr(s).build();

    // We do not tell the tester that we require secret key access
    ProtoKeySerializationTester tester =
        new ProtoKeySerializationTester(
            TYPE_URL, KeyMaterialType.SYMMETRIC, /* requiresSecretKeyAccess = */ false, registry);
    // The tester will pass in no access token, hence we get the GeneralSecurityException directly.
    assertThrows(
        GeneralSecurityException.class,
        () -> tester.testParse(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357));
    assertThrows(
        GeneralSecurityException.class,
        () -> tester.testSerialize(key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            tester.testParseAndSerialize(
                key, proto, OutputPrefixType.TINK, /* idRequirement= */ 1357));
  }

  @Test
  public void testParsingFails_parsingFails_succeeds() throws Exception {
    // Wrong length, so parsing will fail, so "testParsingFail" succeeds.
    ByteString s = ByteString.copyFrom(new byte[] {1, 2, 3, 4, 5});
    TestProto proto = TestProto.newBuilder().setStr(s).build();
    ProtoKeySerializationTester tester =
        new ProtoKeySerializationTester(
            TYPE_URL, KeyMaterialType.SYMMETRIC, /* requiresSecretKeyAccess = */ false, registry);

    tester.testParsingFails(proto, OutputPrefixType.TINK, /* idRequirement= */ 1357);
  }

  @Test
  public void testParsingFails_parsingSucceeds_fails() throws Exception {
    // Correct length, so parsing succeeds, so "testParsingFail" fails.
    ByteString s = ByteString.copyFrom(new byte[] {1, 2, 3, 4});
    TestProto proto = TestProto.newBuilder().setStr(s).build();
    ProtoKeySerializationTester tester =
        new ProtoKeySerializationTester(
            TYPE_URL, KeyMaterialType.SYMMETRIC, /* requiresSecretKeyAccess = */ false, registry);

    assertThrows(
        AssertionError.class,
        () -> tester.testParsingFails(proto, OutputPrefixType.TINK, /* idRequirement= */ 1357));
  }
}
