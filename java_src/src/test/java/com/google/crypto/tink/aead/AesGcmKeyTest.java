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

package com.google.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class AesGcmKeyTest {

  @Test
  public void buildNoPrefixVariantAndGetProperties() throws Exception {
    AesGcmParameters parameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.hasIdRequirement()).isFalse();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    AesGcmKey key = AesGcmKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildTinkVariantAndGetProperties() throws Exception {
    AesGcmParameters parameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(24)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.TINK)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    SecretBytes keyBytes = SecretBytes.randomBytes(24);
    AesGcmKey key =
        AesGcmKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setIdRequirement(0x66AABBCC)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void buildCrunchyVariantAndGetProperties() throws Exception {
    AesGcmParameters parameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.CRUNCHY)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    SecretBytes keyBytes = SecretBytes.randomBytes(32);
    AesGcmKey key =
        AesGcmKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setIdRequirement(0x66AABBCC)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0066AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void emptyBuild_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> AesGcmKey.builder().build());
  }

  @Test
  public void buildWithoutParameters_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> AesGcmKey.builder().setKeyBytes(SecretBytes.randomBytes(32)).build());
  }

  @Test
  public void buildWithoutKeyBytes_fails() throws Exception {
    AesGcmParameters parameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> AesGcmKey.builder().setParameters(parameters).build());
  }

  @Test
  public void paramtersRequireIdButIdIsNotSetInBuild_fails() throws Exception {
    AesGcmParameters parametersWithIdRequirement =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.TINK)
            .build();
    assertThat(parametersWithIdRequirement.hasIdRequirement()).isTrue();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesGcmKey.builder()
                .setKeyBytes(SecretBytes.randomBytes(16))
                .setParameters(parametersWithIdRequirement)
                .build());
  }

  @Test
  public void buildBadKeySize_fails() throws Exception {
    AesGcmParameters parameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesGcmKey.builder()
                .setParameters(parameters)
                .setKeyBytes(SecretBytes.randomBytes(16))
                .build());
  }

  @Test
  public void testEqualities() throws Exception {
    SecretBytes keyBytes32 = SecretBytes.randomBytes(32);
    SecretBytes keyBytes32Copy =
        SecretBytes.copyFrom(
            keyBytes32.toByteArray(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
    SecretBytes keyBytes32Diff = SecretBytes.randomBytes(32);
    SecretBytes keyBytes16 = SecretBytes.randomBytes(16);

    AesGcmParameters noPrefixParametersKeySize32 =
        AesGcmParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(32)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    AesGcmParameters noPrefixParametersKeySize16 =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    AesGcmParameters tinkPrefixParametersKeySize32 =
        AesGcmParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setIvSizeBytes(32)
            .setVariant(AesGcmParameters.Variant.TINK)
            .build();
    AesGcmParameters crunchyPrefixParametersKeySize32 =
        AesGcmParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setIvSizeBytes(32)
            .setVariant(AesGcmParameters.Variant.CRUNCHY)
            .build();

    new KeyTester()
        .addEqualityGroup(
            "No prefix, keyBytes32",
            AesGcmKey.builder()
                .setParameters(noPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .build(),
            // The same key built twice must be equal.
            AesGcmKey.builder()
                .setParameters(noPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .build(),
            // The same key built with a copy of key bytes must be equal.
            AesGcmKey.builder()
                .setParameters(noPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32Copy)
                .build(),
            // Setting id requirement to null is equal to not setting it.
            AesGcmKey.builder()
                .setParameters(noPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .setIdRequirement(null)
                .build())
        // This group checks that keys with different key bytes are not equal.
        .addEqualityGroup(
            "No prefix, newly generated keyBytes32",
            AesGcmKey.builder()
                .setParameters(noPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32Diff)
                .build())
        // This group checks that keys with different key sizes are not equal.
        .addEqualityGroup(
            "No prefix, keyBytes16",
            AesGcmKey.builder()
                .setParameters(noPrefixParametersKeySize16)
                .setKeyBytes(keyBytes16)
                .build())
        .addEqualityGroup(
            "Tink with key id 1907, keyBytes32",
            AesGcmKey.builder()
                .setParameters(tinkPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .setIdRequirement(1907)
                .build(),
            AesGcmKey.builder()
                .setParameters(tinkPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32Copy)
                .setIdRequirement(1907)
                .build())
        // This group checks that keys with different key ids are not equal.
        .addEqualityGroup(
            "Tink with key id 1908, keyBytes32",
            AesGcmKey.builder()
                .setParameters(tinkPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .setIdRequirement(1908)
                .build())
        // This groups checks that keys with different output prefix types are not equal.
        .addEqualityGroup(
            "Crunchy with key id 1907, keyBytes32",
            AesGcmKey.builder()
                .setParameters(crunchyPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .setIdRequirement(1907)
                .build())
        .doTests();
  }

  @Test
  public void testDifferentKeyTypesEquality_fails() throws Exception {
    AesGcmParameters aesGcmParameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();

    AesEaxParameters aesEaxParameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesEaxParameters.Variant.NO_PREFIX)
            .build();

    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    AesEaxKey aesEaxKey =
        AesEaxKey.builder().setParameters(aesEaxParameters).setKeyBytes(keyBytes).build();
    AesGcmKey aesGcmKey =
        AesGcmKey.builder().setParameters(aesGcmParameters).setKeyBytes(keyBytes).build();

    assertThat(aesGcmKey.equalsKey(aesEaxKey)).isFalse();
  }
}
