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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link KeySerializer}. */
@RunWith(JUnit4.class)
public final class KeySerializerTest {

  @Immutable
  private static class ExampleKey extends Key {
    @Override
    public boolean equalsKey(Key k) {
      return k == this;
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
      return null;
    }

    @Override
    public Parameters getParameters() {
      throw new UnsupportedOperationException("Not needed in test");
    }
  }

  @Immutable
  private static class ExampleSerialization implements Serialization {
    @Override
    public Bytes getObjectIdentifier() {
      return Bytes.copyFrom(new byte[0]);
    }
  }

  private static ExampleSerialization serialize(ExampleKey k, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    SecretKeyAccess.requireAccess(access);
    return new ExampleSerialization();
  }

  @Test
  public void createSerializer_works() throws Exception {
    KeySerializer.create(
        KeySerializerTest::serialize, ExampleKey.class, ExampleSerialization.class);
  }

  @Test
  public void createSerializer_serializeKey_works() throws Exception {
    KeySerializer<ExampleKey, ExampleSerialization> serializer =
        KeySerializer.create(
            KeySerializerTest::serialize, ExampleKey.class, ExampleSerialization.class);
    assertThat(serializer.serializeKey(new ExampleKey(), InsecureSecretKeyAccess.get()))
        .isNotNull();
    assertThrows(
        GeneralSecurityException.class,
        () -> serializer.serializeKey(new ExampleKey(), /* access = */ null));
  }

  @Test
  public void createSerializer_classes_work() throws Exception {
    KeySerializer<ExampleKey, ExampleSerialization> serializer =
        KeySerializer.create(
            KeySerializerTest::serialize, ExampleKey.class, ExampleSerialization.class);
    assertThat(serializer.getKeyClass()).isEqualTo(ExampleKey.class);
    assertThat(serializer.getSerializationClass()).isEqualTo(ExampleSerialization.class);
  }
}
