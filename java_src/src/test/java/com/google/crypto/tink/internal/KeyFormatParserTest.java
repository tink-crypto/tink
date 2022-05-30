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

import com.google.crypto.tink.KeyFormat;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link KeyFormatParser}. */
@RunWith(JUnit4.class)
public final class KeyFormatParserTest {

  @Immutable
  private static class ExampleKeyFormat extends KeyFormat {
    @Override
    public boolean hasIdRequirement() {
      return false;
    }
  }

  @Immutable
  private static class ExampleSerialization implements Serialization {
    @Override
    public ByteArray getObjectIdentifier() {
      return ByteArray.copyFrom(new byte[0]);
    }
  }

  private static ExampleKeyFormat parse(ExampleSerialization serialization)
      throws GeneralSecurityException {
    return new ExampleKeyFormat();
  }

  @Test
  public void createParser_works() throws Exception {
    KeyFormatParser.create(
        KeyFormatParserTest::parse, ByteArray.copyFrom(new byte[0]), ExampleSerialization.class);
  }

  @Test
  public void createParser_parseKey_works() throws Exception {
    KeyFormatParser<ExampleSerialization> parser =
        KeyFormatParser.create(
            KeyFormatParserTest::parse,
            ByteArray.copyFrom(new byte[0]),
            ExampleSerialization.class);
    assertThat(parser.parseKeyFormat(new ExampleSerialization())).isNotNull();
  }

  @Test
  public void createParser_classes_work() throws Exception {
    KeyFormatParser<ExampleSerialization> parser =
        KeyFormatParser.create(
            KeyFormatParserTest::parse,
            ByteArray.copyFrom(new byte[] {1, 2, 3}),
            ExampleSerialization.class);
    assertThat(parser.getObjectIdentifier()).isEqualTo(ByteArray.copyFrom(new byte[] {1, 2, 3}));
    assertThat(parser.getSerializationClass()).isEqualTo(ExampleSerialization.class);
  }
}
