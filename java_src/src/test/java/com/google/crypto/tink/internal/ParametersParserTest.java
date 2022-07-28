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

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link ParametersParser}. */
@RunWith(JUnit4.class)
public final class ParametersParserTest {

  @Immutable
  private static class ExampleParameters extends Parameters {
    @Override
    public boolean hasIdRequirement() {
      return false;
    }
  }

  @Immutable
  private static class ExampleSerialization implements Serialization {
    @Override
    public Bytes getObjectIdentifier() {
      return Bytes.copyFrom(new byte[0]);
    }
  }

  private static ExampleParameters parse(ExampleSerialization serialization)
      throws GeneralSecurityException {
    return new ExampleParameters();
  }

  @Test
  public void createParser_works() throws Exception {
    ParametersParser.create(
        ParametersParserTest::parse, Bytes.copyFrom(new byte[0]), ExampleSerialization.class);
  }

  @Test
  public void createParser_parseKey_works() throws Exception {
    ParametersParser<ExampleSerialization> parser =
        ParametersParser.create(
            ParametersParserTest::parse, Bytes.copyFrom(new byte[0]), ExampleSerialization.class);
    assertThat(parser.parseParameters(new ExampleSerialization())).isNotNull();
  }

  @Test
  public void createParser_classes_work() throws Exception {
    ParametersParser<ExampleSerialization> parser =
        ParametersParser.create(
            ParametersParserTest::parse,
            Bytes.copyFrom(new byte[] {1, 2, 3}),
            ExampleSerialization.class);
    assertThat(parser.getObjectIdentifier()).isEqualTo(Bytes.copyFrom(new byte[] {1, 2, 3}));
    assertThat(parser.getSerializationClass()).isEqualTo(ExampleSerialization.class);
  }
}
