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

import com.google.crypto.tink.KeyFormat;
import com.google.crypto.tink.internal.KeyFormatParser;
import com.google.crypto.tink.internal.KeyFormatSerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeyFormatSerialization;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.TestProto;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.Objects;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ProtoKeyFormatSerializationTesterTest {
  private static final String TYPE_URL = "my_type_url";
  private static final Bytes TYPE_URL_BYTES = Bytes.copyFrom(TYPE_URL.getBytes(US_ASCII));

  private static ProtoKeyFormatSerializationTester tester;
  private static MutableSerializationRegistry registry;

  private static class TestKeyFormat extends KeyFormat {
    private final ByteString strOfLength4;
    private final OutputPrefixType outputPrefixType;

    public TestKeyFormat(ByteString strOfLength4, OutputPrefixType outputPrefixType)
        throws GeneralSecurityException {
      if (strOfLength4.size() != 4) {
        throw new GeneralSecurityException("Must have length 4 str");
      }
      this.strOfLength4 = strOfLength4;
      this.outputPrefixType = outputPrefixType;
    }

    @Override
    public boolean hasIdRequirement() {
      return false;
    }

    /** Returns a ByteString of length 4. */
    public ByteString getStr() {
      return strOfLength4;
    }

    public OutputPrefixType getOutputPrefixType() {
      return outputPrefixType;
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof TestKeyFormat)) {
        return false;
      }
      TestKeyFormat other = (TestKeyFormat) o;
      return strOfLength4.equals(other.strOfLength4)
          && outputPrefixType.equals(other.outputPrefixType);
    }

    @Override
    public int hashCode() {
      return Objects.hash(strOfLength4, outputPrefixType);
    }
  }

  private static ProtoKeyFormatSerialization serializeKeyFormat(TestKeyFormat format)
      throws GeneralSecurityException {
    return ProtoKeyFormatSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(TYPE_URL)
            .setValue(TestProto.newBuilder().setStr(format.getStr()).build().toByteString())
            .setOutputPrefixType(format.getOutputPrefixType())
            .build());
  }

  private static TestKeyFormat parseKeyFormat(ProtoKeyFormatSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException("Wrong type URL");
    }
    try {
      TestProto proto =
          TestProto.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
      return new TestKeyFormat(
          proto.getStr(), serialization.getKeyTemplate().getOutputPrefixType());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing failed: ", e);
    }
  }

  @BeforeClass
  public static void registerSerializerAndParser() throws Exception {
    registry = new MutableSerializationRegistry();
    registry.registerKeyFormatParser(
        KeyFormatParser.create(
            ProtoKeyFormatSerializationTesterTest::parseKeyFormat,
            TYPE_URL_BYTES,
            ProtoKeyFormatSerialization.class));
    registry.registerKeyFormatSerializer(
        KeyFormatSerializer.create(
            ProtoKeyFormatSerializationTesterTest::serializeKeyFormat,
            TestKeyFormat.class,
            ProtoKeyFormatSerialization.class));
    tester = new ProtoKeyFormatSerializationTester(TYPE_URL, registry);
  }

  @Test
  public void testParseAndSerialize_testerWorksIfCorrect() throws Exception {
    ByteString s = ByteString.copyFrom(new byte[] {1, 2, 3, 4});
    TestKeyFormat format = new TestKeyFormat(s, OutputPrefixType.TINK);

    TestProto proto = TestProto.newBuilder().setStr(format.getStr()).build();

    tester.testParse(format, proto, OutputPrefixType.TINK);
    tester.testSerialize(format, proto, OutputPrefixType.TINK);
    tester.testParseAndSerialize(format, proto, OutputPrefixType.TINK);
  }

  @Test
  public void testParseAndSerialize_testWrongOutputPrefix() throws Exception {
    ByteString s = ByteString.copyFrom(new byte[] {1, 2, 3, 4});
    TestKeyFormat format = new TestKeyFormat(s, OutputPrefixType.TINK);

    TestProto proto = TestProto.newBuilder().setStr(format.getStr()).build();

    assertThrows(
        AssertionError.class, () -> tester.testParse(format, proto, OutputPrefixType.CRUNCHY));
    assertThrows(
        AssertionError.class, () -> tester.testSerialize(format, proto, OutputPrefixType.CRUNCHY));
    assertThrows(
        AssertionError.class,
        () -> tester.testParseAndSerialize(format, proto, OutputPrefixType.CRUNCHY));
  }

  @Test
  public void testParseAndSerialize_testWrongProto() throws Exception {
    ByteString s = ByteString.copyFrom(new byte[] {1, 2, 3, 4});
    TestKeyFormat format = new TestKeyFormat(s, OutputPrefixType.TINK);

    TestProto proto =
        TestProto.newBuilder().setStr(ByteString.copyFrom(new byte[] {2, 3, 4, 5})).build();

    assertThrows(
        AssertionError.class, () -> tester.testParse(format, proto, OutputPrefixType.TINK));
    assertThrows(
        AssertionError.class, () -> tester.testSerialize(format, proto, OutputPrefixType.TINK));
    assertThrows(
        AssertionError.class,
        () -> tester.testParseAndSerialize(format, proto, OutputPrefixType.TINK));
  }

  @Test
  public void testSerialize_testWrongTypeUrl() throws Exception {
    ByteString s = ByteString.copyFrom(new byte[] {1, 2, 3, 4});
    TestKeyFormat format = new TestKeyFormat(s, OutputPrefixType.TINK);

    ProtoKeyFormatSerializationTester testerWrongTypeUrl =
        new ProtoKeyFormatSerializationTester("different type url", registry);

    TestProto proto = TestProto.newBuilder().setStr(s).build();

    assertThrows(
        AssertionError.class,
        () -> testerWrongTypeUrl.testSerialize(format, proto, OutputPrefixType.TINK));
  }

  @Test
  public void testParse_testParsingFails_works() throws Exception {
    // This is a wrong length, so the parsing fails, so the test that the parsing fails succeeds.
    ByteString s = ByteString.copyFrom(new byte[] {1, 2, 3, 4, 5});
    TestProto proto = TestProto.newBuilder().setStr(s).build();
    tester.testParsingFails(proto, OutputPrefixType.TINK);
  }

  @Test
  public void testParse_testParsingFails_fails() throws Exception {
    // This is the right length, so the parsing succeeds, so the test that the parsing fails fails.
    ByteString s = ByteString.copyFrom(new byte[] {1, 2, 3, 4});
    TestProto proto = TestProto.newBuilder().setStr(s).build();
    assertThrows(AssertionError.class, () -> tester.testParsingFails(proto, OutputPrefixType.TINK));
  }
}
