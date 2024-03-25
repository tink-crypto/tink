// Copyright 2023 Google Inc.
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

package com.google.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyKmsAeadKeyTest {

  @Test
  public void createKeyAndGetProperties() throws Exception {
    LegacyKmsAeadParameters parameters = LegacyKmsAeadParameters.create("someArbitrarykeyUri223");
    assertThat(parameters.keyUri()).isEqualTo("someArbitrarykeyUri223");
    assertThat(parameters.variant()).isEqualTo(LegacyKmsAeadParameters.Variant.NO_PREFIX);

    LegacyKmsAeadKey key = LegacyKmsAeadKey.create(parameters);

    assertThat(key.getOutputPrefix().size()).isEqualTo(0);
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void createNoPrefixKeyAndGetProperties() throws Exception {
    LegacyKmsAeadParameters parameters =
        LegacyKmsAeadParameters.create(
            "someArbitrarykeyUri223", LegacyKmsAeadParameters.Variant.NO_PREFIX);
    assertThat(parameters.keyUri()).isEqualTo("someArbitrarykeyUri223");
    assertThat(parameters.variant()).isEqualTo(LegacyKmsAeadParameters.Variant.NO_PREFIX);

    LegacyKmsAeadKey key = LegacyKmsAeadKey.create(parameters, null);

    assertThat(key.getOutputPrefix().size()).isEqualTo(0);
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void createTinkKeyAndGetProperties() throws Exception {
    LegacyKmsAeadParameters parameters =
        LegacyKmsAeadParameters.create(
            "someArbitrarykeyUri223", LegacyKmsAeadParameters.Variant.TINK);
    assertThat(parameters.keyUri()).isEqualTo("someArbitrarykeyUri223");
    assertThat(parameters.variant()).isEqualTo(LegacyKmsAeadParameters.Variant.TINK);

    LegacyKmsAeadKey key = LegacyKmsAeadKey.create(parameters, 0x0708090a);

    assertThat(key.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {0x01, 0x07, 0x08, 0x09, 0x0a}));
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x708090a);
  }

  @Test
  public void wrongIdRequirement_throws() throws Exception {
    LegacyKmsAeadParameters parametersNoPrefix =
        LegacyKmsAeadParameters.create("keyUri1", LegacyKmsAeadParameters.Variant.NO_PREFIX);
    LegacyKmsAeadParameters parametersTink =
        LegacyKmsAeadParameters.create("keyUri2", LegacyKmsAeadParameters.Variant.TINK);

    assertThrows(
        GeneralSecurityException.class,
        () -> LegacyKmsAeadKey.create(parametersNoPrefix, /* idRequirement= */ 0x0708090a));
    assertThrows(
        GeneralSecurityException.class,
        () -> LegacyKmsAeadKey.create(parametersTink, /* idRequirement= */ null));
    assertThrows(GeneralSecurityException.class, () -> LegacyKmsAeadKey.create(parametersTink));
  }

  @Test
  public void testNoPrefixEqualKey() throws Exception {
    LegacyKmsAeadParameters parameters1 = LegacyKmsAeadParameters.create("someArbitrarykeyUri223");
    LegacyKmsAeadParameters parameters1Copy =
        LegacyKmsAeadParameters.create("someArbitrarykeyUri223");
    LegacyKmsAeadParameters parameters2 = LegacyKmsAeadParameters.create("someArbitrarykeyUri334");

    LegacyKmsAeadKey key1 = LegacyKmsAeadKey.create(parameters1);
    LegacyKmsAeadKey key1Copy = LegacyKmsAeadKey.create(parameters1Copy);
    LegacyKmsAeadKey key2 = LegacyKmsAeadKey.create(parameters2);

    assertTrue(key1.equalsKey(key1Copy));
    assertFalse(key1.equalsKey(key2));
  }

  @Test
  public void testTinkEqualKey() throws Exception {
    LegacyKmsAeadParameters parametersTink =
        LegacyKmsAeadParameters.create("keyUri", LegacyKmsAeadParameters.Variant.TINK);
    LegacyKmsAeadKey keyTink = LegacyKmsAeadKey.create(parametersTink, /* idRequirement= */ 123);
    LegacyKmsAeadKey keyTinkCopy =
        LegacyKmsAeadKey.create(
            LegacyKmsAeadParameters.create("keyUri", LegacyKmsAeadParameters.Variant.TINK),
            /* idRequirement= */ 123);
    LegacyKmsAeadKey keyTink2 = LegacyKmsAeadKey.create(parametersTink, /* idRequirement= */ 234);
    LegacyKmsAeadKey keyNoPrefix =
        LegacyKmsAeadKey.create(
            LegacyKmsAeadParameters.create("keyUri", LegacyKmsAeadParameters.Variant.NO_PREFIX),
            /* idRequirement= */ null);

    assertTrue(keyTink.equalsKey(keyTinkCopy));
    assertFalse(keyTink.equalsKey(keyTink2));
    assertFalse(keyTink.equalsKey(keyNoPrefix));
  }

  @Test
  public void testDifferentKeyTypesEquality_fails() throws Exception {
    LegacyKmsAeadParameters parameters = LegacyKmsAeadParameters.create("someArbitrarykeyUri223");
    LegacyKmsAeadKey key = LegacyKmsAeadKey.create(parameters);

    XChaCha20Poly1305Key xChaCha20Poly1305Key =
        XChaCha20Poly1305Key.create(SecretBytes.randomBytes(32));

    assertThat(key.equalsKey(xChaCha20Poly1305Key)).isFalse();
  }
}
