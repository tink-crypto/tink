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
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link KeyFormatSerializer}. */
@RunWith(JUnit4.class)
public final class KeyFormatSerializerTest {

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
    public Bytes getObjectIdentifier() {
      return Bytes.copyFrom(new byte[0]);
    }
  }

  private static ExampleSerialization serialize(ExampleKeyFormat k)
      throws GeneralSecurityException {
    return new ExampleSerialization();
  }

  @Test
  public void createSerializer_works() throws Exception {
    KeyFormatSerializer.create(
        KeyFormatSerializerTest::serialize, ExampleKeyFormat.class, ExampleSerialization.class);
  }

  @Test
  public void createSerializer_serializeKey_works() throws Exception {
    KeyFormatSerializer<ExampleKeyFormat, ExampleSerialization> serializer =
        KeyFormatSerializer.create(
            KeyFormatSerializerTest::serialize, ExampleKeyFormat.class, ExampleSerialization.class);
    assertThat(serializer.serializeKeyFormat(new ExampleKeyFormat())).isNotNull();
  }

  @Test
  public void createSerializer_classes_work() throws Exception {
    KeyFormatSerializer<ExampleKeyFormat, ExampleSerialization> serializer =
        KeyFormatSerializer.create(
            KeyFormatSerializerTest::serialize, ExampleKeyFormat.class, ExampleSerialization.class);
    assertThat(serializer.getKeyFormatClass()).isEqualTo(ExampleKeyFormat.class);
    assertThat(serializer.getSerializationClass()).isEqualTo(ExampleSerialization.class);
  }
}
