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

import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.TestProto;
import com.google.crypto.tink.util.Bytes;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@code ProtoParametersSerialization} */
@RunWith(JUnit4.class)
public final class ProtoParametersSerializationTest {
  @Test
  public void testCreationAndValues_basic() throws Exception {
    KeyTemplate template = KeyTemplate.newBuilder().setTypeUrl("myTypeUrl").build();
    ProtoParametersSerialization serialization = ProtoParametersSerialization.create(template);
    assertThat(serialization.getKeyTemplate()).isEqualTo(template);
    assertThat(serialization.getObjectIdentifier())
        .isEqualTo(Bytes.copyFrom("myTypeUrl".getBytes(UTF_8)));
  }

  @Test
  public void testCreationFromParts_basic() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "typeUrl", OutputPrefixType.RAW, TestProto.newBuilder().setNum(13234).build());
    assertThat(serialization.getKeyTemplate().getTypeUrl()).isEqualTo("typeUrl");
    assertThat(serialization.getObjectIdentifier())
        .isEqualTo(Bytes.copyFrom("typeUrl".getBytes(UTF_8)));
    assertThat(serialization.getKeyTemplate().getOutputPrefixType())
        .isEqualTo(OutputPrefixType.RAW);
    TestProto parsedProto = TestProto.parseFrom(serialization.getKeyTemplate().getValue());
    assertThat(parsedProto.getNum()).isEqualTo(13234);
  }
}
