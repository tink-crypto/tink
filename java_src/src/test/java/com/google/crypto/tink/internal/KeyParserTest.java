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
import com.google.crypto.tink.KeyFormat;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link KeyParser}. */
@RunWith(JUnit4.class)
public final class KeyParserTest {

  @Immutable
  private static class ExampleKey extends Key {
    @Override
    public boolean equalsKey(Key k) {
      return k == this;
    }

    @Override
    public Optional<Integer> getIdRequirement() {
      return Optional.empty();
    }

    @Override
    public KeyFormat getKeyFormat() {
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

  private static ExampleKey parse(
      ExampleSerialization serialization, Optional<SecretKeyAccess> access)
      throws GeneralSecurityException {
    SecretKeyAccess.requireAccess(access);
    return new ExampleKey();
  }

  @Test
  public void createParser_works() throws Exception {
    KeyParser.create(KeyParserTest::parse, Bytes.copyFrom(new byte[0]), ExampleSerialization.class);
  }

  @Test
  public void createParser_parseKey_works() throws Exception {
    KeyParser<ExampleSerialization> parser =
        KeyParser.create(
            KeyParserTest::parse, Bytes.copyFrom(new byte[0]), ExampleSerialization.class);
    assertThat(
            parser.parseKey(new ExampleSerialization(), Optional.of(InsecureSecretKeyAccess.get())))
        .isNotNull();
    assertThrows(
        GeneralSecurityException.class,
        () -> parser.parseKey(new ExampleSerialization(), Optional.empty()));
  }

  @Test
  public void createParser_classes_work() throws Exception {
    KeyParser<ExampleSerialization> parser =
        KeyParser.create(
            KeyParserTest::parse, Bytes.copyFrom(new byte[] {1, 2, 3}), ExampleSerialization.class);
    assertThat(parser.getObjectIdentifier()).isEqualTo(Bytes.copyFrom(new byte[] {1, 2, 3}));
    assertThat(parser.getSerializationClass()).isEqualTo(ExampleSerialization.class);
  }
}
