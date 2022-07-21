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

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.errorprone.annotations.Immutable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ParametersWithSerializationTest {
  @Immutable
  private static final class TestParameters extends Parameters {
    public TestParameters() {}

    @Override
    public boolean hasIdRequirement() {
      return false;
    }
  }

  @Test
  public void testAll() throws Exception {
    Parameters parameters = new TestParameters();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(KeyTemplate.getDefaultInstance());
    ParametersWithSerialization parametersWithSerialization =
        new ParametersWithSerialization(parameters, serialization);
    assertThat(parametersWithSerialization.getParameters()).isSameInstanceAs(parameters);
    assertThat(parametersWithSerialization.getSerializedParameters())
        .isSameInstanceAs(serialization);
  }
}
