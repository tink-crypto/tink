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

import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.TestProto;
import com.google.crypto.tink.subtle.Hex;
import com.google.protobuf.ByteString;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class AssertsTest {
  @Test
  public void testEqualFormat() throws Exception {
    ProtoParametersSerialization serialization1 =
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setOutputPrefixType(OutputPrefixType.RAW)
                .setTypeUrl("TYPE_URL")
                .setValue(TestProto.newBuilder().setNum(1).build().toByteString())
                .build());
    ProtoParametersSerialization serialization2 =
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setOutputPrefixType(OutputPrefixType.RAW)
                .setTypeUrl("TYPE_URL")
                .setValue(TestProto.newBuilder().setNum(1).build().toByteString())
                .build());
    Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2);
  }

  @Test
  public void testEqualFormat_differentEncoding() throws Exception {
    // Encoding, 0x0800, in binary: 0000 1000 0000 0000
    //                              |----||-| |-------|
    //                               (1)  (2)  (3):
    // (1): Field number 1
    // (2): Wire type 0 (Varint)
    // (3): Value 0.
    // This is the same as the default value, which has empty encoding.
    ProtoParametersSerialization serialization1 =
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setOutputPrefixType(OutputPrefixType.RAW)
                .setTypeUrl("TYPE_URL")
                .setValue(ByteString.copyFrom(Hex.decode("0800")))
                .build());
    ProtoParametersSerialization serialization2 =
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setOutputPrefixType(OutputPrefixType.RAW)
                .setTypeUrl("TYPE_URL")
                .setValue(ByteString.EMPTY)
                .build());
    Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2);
  }

  @Test
  public void testEqualFormat_differentOrder() throws Exception {
    // Encoding, 0x0801, in binary: 0000 1000 0000 0001
    //                              |----||-| |-------|
    //                               (1)  (2)  (3):
    // (1): Field number 1
    // (2): Wire type 0 (Varint)
    // (3): Value 1.
    //
    // Encoding 0x120100, in binary: 0001 0010 0000 0001 0000 0000
    //                               |----||-| |-------| |-------|
    //                                (1)  (2)  (3)        (4)
    // (1): Field number 2
    // (2): Wire type 2 (Length Delimeted)
    // (3): Varint (length): 1
    // (4): Data (0x00)
    ProtoParametersSerialization serialization1 =
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setOutputPrefixType(OutputPrefixType.RAW)
                .setTypeUrl("TYPE_URL")
                .setValue(ByteString.copyFrom(Hex.decode("0801120100")))
                .build());
    ProtoParametersSerialization serialization2 =
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setOutputPrefixType(OutputPrefixType.RAW)
                .setTypeUrl("TYPE_URL")
                .setValue(ByteString.copyFrom(Hex.decode("1201000801")))
                .build());
    Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2);
  }

  @Test
  public void testDifferentFormat_outputPrefix_throws() throws Exception {
    ProtoParametersSerialization serialization1 =
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setOutputPrefixType(OutputPrefixType.RAW)
                .setTypeUrl("TYPE_URL")
                .setValue(TestProto.newBuilder().setNum(1).build().toByteString())
                .build());
    ProtoParametersSerialization serialization2 =
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setOutputPrefixType(OutputPrefixType.TINK)
                .setTypeUrl("TYPE_URL")
                .setValue(TestProto.newBuilder().setNum(1).build().toByteString())
                .build());
    assertThrows(
        AssertionError.class,
        () ->
            Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2));
  }

  @Test
  public void testDifferentFormat_typeUrl_throws() throws Exception {
    ProtoParametersSerialization serialization1 =
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setOutputPrefixType(OutputPrefixType.RAW)
                .setTypeUrl("TYPE_URL1")
                .setValue(TestProto.newBuilder().setNum(1).build().toByteString())
                .build());
    ProtoParametersSerialization serialization2 =
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setOutputPrefixType(OutputPrefixType.RAW)
                .setTypeUrl("TYPE_URL2")
                .setValue(TestProto.newBuilder().setNum(1).build().toByteString())
                .build());
    assertThrows(
        AssertionError.class,
        () ->
            Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2));
  }

  @Test
  public void testDifferentFormat_value_throws() throws Exception {
    ProtoParametersSerialization serialization1 =
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setOutputPrefixType(OutputPrefixType.RAW)
                .setTypeUrl("TYPE_URL")
                .setValue(TestProto.newBuilder().setNum(1).build().toByteString())
                .build());
    ProtoParametersSerialization serialization2 =
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setOutputPrefixType(OutputPrefixType.RAW)
                .setTypeUrl("TYPE_URL")
                .setValue(TestProto.newBuilder().setNum(2).build().toByteString())
                .build());
    assertThrows(
        AssertionError.class,
        () ->
            Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2));
  }

  @Test
  public void testEqualFormat_unparseable_throws() throws Exception {
    // Proto messages start with a VarInt, which always ends with a byte with most significant bit
    // unset. 0x80 is hence invalid.
    ProtoParametersSerialization serialization1 =
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setOutputPrefixType(OutputPrefixType.RAW)
                .setTypeUrl("TYPE_URL")
                .setValue(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                .build());
    ProtoParametersSerialization serialization2 =
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setOutputPrefixType(OutputPrefixType.RAW)
                .setTypeUrl("TYPE_URL")
                .setValue(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                .build());
    assertThrows(
        AssertionError.class,
        () ->
            Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2));
  }

  @Test
  public void testEqualKey() throws Exception {
    ProtoKeySerialization serialization1 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            TestProto.newBuilder().setNum(1).build().toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    ProtoKeySerialization serialization2 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            TestProto.newBuilder().setNum(1).build().toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2);
  }

  @Test
  public void testEqualKey_defaultValue() throws Exception {
    // Encoding, 0x0800, in binary: 0000 1000 0000 0000
    //                              |----||-| |-------|
    //                               (1)  (2)  (3):
    // (1): Field number 1
    // (2): Wire type 0 (Varint)
    // (3): Value 0.
    // This is the same as the default value, which has empty encoding.
    ProtoKeySerialization serialization1 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            ByteString.copyFrom(Hex.decode("0800")),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    ProtoKeySerialization serialization2 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2);
  }

  @Test
  public void testEqualKey_differentOrder() throws Exception {
    // Encoding, 0x0801, in binary: 0000 1000 0000 0001
    //                              |----||-| |-------|
    //                               (1)  (2)  (3):
    // (1): Field number 1
    // (2): Wire type 0 (Varint)
    // (3): Value 1.
    //
    // Encoding 0x120100, in binary: 0001 0010 0000 0001 0000 0000
    //                               |----||-| |-------| |-------|
    //                                (1)  (2)  (3)        (4)
    // (1): Field number 2
    // (2): Wire type 2 (Length Delimeted)
    // (3): Varint (length): 1
    // (4): Data (0x00)
    ProtoKeySerialization serialization1 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            ByteString.copyFrom(Hex.decode("0801120100")),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    ProtoKeySerialization serialization2 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            ByteString.copyFrom(Hex.decode("1201000801")),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2);
  }

  @Test
  public void testDifferentKey_typeUrl_throws() throws Exception {
    ProtoKeySerialization serialization1 =
        ProtoKeySerialization.create(
            "TYPE_URL1",
            TestProto.newBuilder().setNum(1).build().toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    ProtoKeySerialization serialization2 =
        ProtoKeySerialization.create(
            "TYPE_URL2",
            TestProto.newBuilder().setNum(1).build().toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    assertThrows(
        AssertionError.class,
        () ->
            Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2));
  }

  @Test
  public void testDifferentKey_value_throws() throws Exception {
    ProtoKeySerialization serialization1 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            TestProto.newBuilder().setNum(1).build().toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    ProtoKeySerialization serialization2 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            TestProto.newBuilder().setNum(2).build().toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    assertThrows(
        AssertionError.class,
        () ->
            Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2));
  }

  @Test
  public void testDifferentKey_keyMaterialType_throws() throws Exception {
    ProtoKeySerialization serialization1 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            TestProto.newBuilder().setNum(1).build().toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    ProtoKeySerialization serialization2 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            TestProto.newBuilder().setNum(1).build().toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    assertThrows(
        AssertionError.class,
        () ->
            Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2));
  }

  @Test
  public void testDifferentKey_outputPrefixType_throws() throws Exception {
    ProtoKeySerialization serialization1 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            TestProto.newBuilder().setNum(1).build().toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    ProtoKeySerialization serialization2 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            TestProto.newBuilder().setNum(1).build().toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.CRUNCHY,
            /*idRequirement= */ 1234);
    assertThrows(
        AssertionError.class,
        () ->
            Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2));
  }

  @Test
  public void testDifferentKey_idRequirement_throws() throws Exception {
    ProtoKeySerialization serialization1 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            TestProto.newBuilder().setNum(1).build().toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    ProtoKeySerialization serialization2 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            TestProto.newBuilder().setNum(1).build().toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1235);
    assertThrows(
        AssertionError.class,
        () ->
            Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2));
  }

  @Test
  public void testDifferentKey_unparseable_throws() throws Exception {
    // Proto messages start with a VarInt, which always ends with a byte with most significant bit
    // unset. 0x80 is hence invalid.
    ProtoKeySerialization serialization1 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            ByteString.copyFrom(new byte[] {(byte) 0x80}),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    ProtoKeySerialization serialization2 =
        ProtoKeySerialization.create(
            "TYPE_URL",
            ByteString.copyFrom(new byte[] {(byte) 0x80}),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement= */ 1234);
    assertThrows(
        AssertionError.class,
        () ->
            Asserts.assertEqualWhenValueParsed(TestProto.parser(), serialization1, serialization2));
  }
}
