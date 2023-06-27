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

package com.google.crypto.tink.keyderivation;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.aead.AesEaxParameters;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.prf.HmacPrfKey;
import com.google.crypto.tink.prf.HmacPrfParameters;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class PrfBasedKeyDerivationKeyTest {

  @Test
  public void testCreateAndValues_basic() throws Exception {
    HmacPrfParameters hmacPrfParameters =
        HmacPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();
    HmacPrfKey prfKey =
        HmacPrfKey.builder()
            .setParameters(hmacPrfParameters)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(
                AesEaxParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.TINK)
                    .build())
            .setPrfParameters(hmacPrfParameters)
            .build();
    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ 102);

    assertThat(keyDerivationKey).isNotNull();
    assertThat(keyDerivationKey.getParameters()).isEqualTo(derivationParameters);
    assertThat(keyDerivationKey.getPrfKey().equalsKey(prfKey)).isTrue();
    assertThat(keyDerivationKey.getIdRequirementOrNull()).isEqualTo(102);
  }

  @Test
  public void testCreate_noIdRequirement_works() throws Exception {
    HmacPrfParameters hmacPrfParameters =
        HmacPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();
    HmacPrfKey prfKey =
        HmacPrfKey.builder()
            .setParameters(hmacPrfParameters)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(
                AesEaxParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(16)
                    // Derived Key does not want an ID requirement:
                    .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                    .build())
            .setPrfParameters(hmacPrfParameters)
            .build();
    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ null);

    assertThat(keyDerivationKey).isNotNull();
    assertThat(keyDerivationKey.getParameters()).isEqualTo(derivationParameters);
    assertThat(keyDerivationKey.getPrfKey().equalsKey(prfKey)).isTrue();
    assertThat(keyDerivationKey.getIdRequirementOrNull()).isEqualTo(null);
  }

  @Test
  public void testCreate_idRequirementWithMissingVariant_throws() throws Exception {
    HmacPrfParameters hmacPrfParameters =
        HmacPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();
    HmacPrfKey prfKey =
        HmacPrfKey.builder()
            .setParameters(hmacPrfParameters)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(
                AesEaxParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(16)
                    // Derived Key does not want an ID requirement:
                    .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                    .build())
            .setPrfParameters(hmacPrfParameters)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ 12));
  }

  @Test
  public void testCreate_prefixVariantWithMissingIdRequirement_throws() throws Exception {
    HmacPrfParameters hmacPrfParameters =
        HmacPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();
    HmacPrfKey prfKey =
        HmacPrfKey.builder()
            .setParameters(hmacPrfParameters)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(
                AesEaxParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.TINK)
                    .build())
            .setPrfParameters(hmacPrfParameters)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            PrfBasedKeyDerivationKey.create(
                derivationParameters, prfKey, /* idRequirement= */ null));
  }

  @Test
  public void testCreate_mismatchedPrfParmetersAndKey_throws() throws Exception {
    HmacPrfParameters hmacPrfParameters1 =
        HmacPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();
    HmacPrfParameters hmacPrfParameters2 =
        HmacPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();
    HmacPrfKey prfKey =
        HmacPrfKey.builder()
            .setParameters(hmacPrfParameters1)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(
                AesEaxParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.TINK)
                    .build())
            .setPrfParameters(hmacPrfParameters2)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            PrfBasedKeyDerivationKey.create(
                derivationParameters, prfKey, /* idRequirement= */ 102));
  }

  @Test
  public void testEqualities() throws Exception {
    // We make copies in various places of inner objects to ensure that the code doesn't
    // use == but ".equals()"
    HmacPrfParameters hmacPrfParameters =
        HmacPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();
    HmacPrfKey prfKey =
        HmacPrfKey.builder()
            .setParameters(hmacPrfParameters)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();
    HmacPrfKey prfKeyCopy =
        HmacPrfKey.builder()
            .setParameters(hmacPrfParameters)
            .setKeyBytes(prfKey.getKeyBytes())
            .build();

    HmacPrfKey prfKey2 =
        HmacPrfKey.builder()
            .setParameters(hmacPrfParameters)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();

    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(
                AesEaxParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.TINK)
                    .build())
            .setPrfParameters(hmacPrfParameters)
            .build();
    PrfBasedKeyDerivationParameters derivationParametersCopy =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(
                AesEaxParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.TINK)
                    .build())
            .setPrfParameters(hmacPrfParameters)
            .build();
    PrfBasedKeyDerivationParameters derivationParameters2 =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(
                AesEaxParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.CRUNCHY)
                    .build())
            .setPrfParameters(hmacPrfParameters)
            .build();
    PrfBasedKeyDerivationParameters derivationParametersNoPrefix =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(
                AesEaxParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                    .build())
            .setPrfParameters(hmacPrfParameters)
            .build();

    new KeyTester()
        .addEqualityGroup(
            "derivationParameters, prfKey, ID 101",
            PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ 101),
            PrfBasedKeyDerivationKey.create(
                derivationParametersCopy, prfKey, /* idRequirement= */ 101),
            PrfBasedKeyDerivationKey.create(
                derivationParameters, prfKeyCopy, /* idRequirement= */ 101))
        .addEqualityGroup(
            "derivationParameters, prfKey, ID 102",
            PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ 102))
        .addEqualityGroup(
            "derivationParameters, prfKey2, ID 101",
            PrfBasedKeyDerivationKey.create(
                derivationParameters, prfKey2, /* idRequirement= */ 101))
        .addEqualityGroup(
            "derivationParameters2, prfKey, ID 101",
            PrfBasedKeyDerivationKey.create(
                derivationParameters2, prfKey, /* idRequirement= */ 101))
        .addEqualityGroup(
            "derivationParametersNoPrefix, prfKey",
            PrfBasedKeyDerivationKey.create(
                derivationParametersNoPrefix, prfKey, /* idRequirement= */ null))
        .doTests();
  }
}
