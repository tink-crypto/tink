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

import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.proto.OutputPrefixType;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link EnumTypeProtoConverter}. */
@RunWith(JUnit4.class)
public final class EnumTypeProtoConverterTest {
  @Test
  public void toProtoEnum_succeedsWithAddedEnums() throws Exception {
    EnumTypeProtoConverter<OutputPrefixType, HpkeParameters.Variant> converter =
        EnumTypeProtoConverter.<OutputPrefixType, HpkeParameters.Variant>builder()
            .add(OutputPrefixType.RAW, HpkeParameters.Variant.NO_PREFIX)
            .add(OutputPrefixType.TINK, HpkeParameters.Variant.TINK)
            .add(OutputPrefixType.CRUNCHY, HpkeParameters.Variant.CRUNCHY)
            .build();

    assertThat(converter.toProtoEnum(HpkeParameters.Variant.NO_PREFIX))
        .isEqualTo(OutputPrefixType.RAW);
    assertThat(converter.toProtoEnum(HpkeParameters.Variant.TINK)).isEqualTo(OutputPrefixType.TINK);
    assertThat(converter.toProtoEnum(HpkeParameters.Variant.CRUNCHY))
        .isEqualTo(OutputPrefixType.CRUNCHY);
  }

  @Test
  public void toProtoEnum_failsWithMissingEnums() throws Exception {
    EnumTypeProtoConverter<OutputPrefixType, HpkeParameters.Variant> converterWithoutCrunchy =
        EnumTypeProtoConverter.<OutputPrefixType, HpkeParameters.Variant>builder()
            .add(OutputPrefixType.RAW, HpkeParameters.Variant.NO_PREFIX)
            .add(OutputPrefixType.TINK, HpkeParameters.Variant.TINK)
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> converterWithoutCrunchy.toProtoEnum(HpkeParameters.Variant.CRUNCHY));
  }

  @Test
  public void fromProtoEnum_succeedsWithAddedEnums() throws Exception {
    EnumTypeProtoConverter<OutputPrefixType, HpkeParameters.Variant> converter =
        EnumTypeProtoConverter.<OutputPrefixType, HpkeParameters.Variant>builder()
            .add(OutputPrefixType.RAW, HpkeParameters.Variant.NO_PREFIX)
            .add(OutputPrefixType.TINK, HpkeParameters.Variant.TINK)
            .add(OutputPrefixType.CRUNCHY, HpkeParameters.Variant.CRUNCHY)
            .build();

    assertThat(converter.fromProtoEnum(OutputPrefixType.RAW))
        .isEqualTo(HpkeParameters.Variant.NO_PREFIX);
    assertThat(converter.fromProtoEnum(OutputPrefixType.TINK))
        .isEqualTo(HpkeParameters.Variant.TINK);
    assertThat(converter.fromProtoEnum(OutputPrefixType.CRUNCHY))
        .isEqualTo(HpkeParameters.Variant.CRUNCHY);
  }

  @Test
  public void fromProtoEnum_failsWithMissingEnums() throws Exception {
    EnumTypeProtoConverter<OutputPrefixType, HpkeParameters.Variant> converterWithoutCrunchy =
        EnumTypeProtoConverter.<OutputPrefixType, HpkeParameters.Variant>builder()
            .add(OutputPrefixType.RAW, HpkeParameters.Variant.NO_PREFIX)
            .add(OutputPrefixType.TINK, HpkeParameters.Variant.TINK)
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> converterWithoutCrunchy.fromProtoEnum(OutputPrefixType.CRUNCHY));
  }
}
