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

import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ByteString;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyProtoKeyFormatTest {
  @Test
  public void create_works() {
    KeyTemplate template =
        KeyTemplate.newBuilder()
            .setTypeUrl("TypeUrl")
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setValue(ByteString.EMPTY)
            .build();
    ProtoKeyFormatSerialization serialization = ProtoKeyFormatSerialization.create(template);
    LegacyProtoKeyFormat format = new LegacyProtoKeyFormat(serialization);
    assertThat(format.getSerialization()).isSameInstanceAs(serialization);
  }

  private static LegacyProtoKeyFormat fromBuilder(KeyTemplate.Builder builder) {
    return new LegacyProtoKeyFormat(ProtoKeyFormatSerialization.create(builder.build()));
  }

  @Test
  public void create_hasIdRequirement() {
    KeyTemplate.Builder builder =
        KeyTemplate.newBuilder().setTypeUrl("TypeUrl").setValue(ByteString.EMPTY);
    assertThat(fromBuilder(builder.setOutputPrefixType(OutputPrefixType.TINK)).hasIdRequirement())
        .isTrue();
    assertThat(
            fromBuilder(builder.setOutputPrefixType(OutputPrefixType.CRUNCHY)).hasIdRequirement())
        .isTrue();
    assertThat(fromBuilder(builder.setOutputPrefixType(OutputPrefixType.LEGACY)).hasIdRequirement())
        .isTrue();
    assertThat(fromBuilder(builder.setOutputPrefixType(OutputPrefixType.RAW)).hasIdRequirement())
        .isFalse();
  }

  @Test
  public void testEquals() {
    KeyTemplate.Builder builder =
        KeyTemplate.newBuilder()
            .setTypeUrl("TypeUrl")
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setValue(ByteString.EMPTY);
    assertThat(fromBuilder(builder)).isEqualTo(fromBuilder(builder));
    assertThat(fromBuilder(builder.setTypeUrl("one")))
        .isNotEqualTo(fromBuilder(builder.setTypeUrl("two")));
    assertThat(fromBuilder(builder.setOutputPrefixType(OutputPrefixType.TINK)))
        .isNotEqualTo(fromBuilder(builder.setOutputPrefixType(OutputPrefixType.CRUNCHY)));
    assertThat(fromBuilder(builder.setValue(ByteString.copyFrom(new byte[] {0}))))
        .isNotEqualTo(fromBuilder(builder.setValue(ByteString.copyFrom(new byte[] {1}))));
  }

  @Test
  public void testHashCode() {
    KeyTemplate.Builder builder =
        KeyTemplate.newBuilder()
            .setTypeUrl("TypeUrl")
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setValue(ByteString.EMPTY);
    assertThat(fromBuilder(builder).hashCode()).isEqualTo(fromBuilder(builder).hashCode());

    builder.setValue(ByteString.EMPTY);
    assertThat(fromBuilder(builder).hashCode()).isEqualTo(fromBuilder(builder).hashCode());
  }
}
