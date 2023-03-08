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
public final class AesEaxKeyTest {

  @Test
  public void buildNoPrefixVariantAndGetProperties() throws Exception {
    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesEaxParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.hasIdRequirement()).isFalse();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    AesEaxKey key = AesEaxKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildTinkVariantAndGetProperties() throws Exception {
    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesEaxParameters.Variant.TINK)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    AesEaxKey key =
        AesEaxKey.builder()
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
    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesEaxParameters.Variant.CRUNCHY)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    AesEaxKey key =
        AesEaxKey.builder()
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
    assertThrows(GeneralSecurityException.class, () -> AesEaxKey.builder().build());
  }

  @Test
  public void buildWithoutParameters_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> AesEaxKey.builder().setKeyBytes(SecretBytes.randomBytes(32)).build());
  }

  @Test
  public void buildWithoutKeyBytes_fails() throws Exception {
    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesEaxParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> AesEaxKey.builder().setParameters(parameters).build());
  }

  @Test
  public void paramtersRequireIdButIdIsNotSetInBuild_fails() throws Exception {
    AesEaxParameters parametersWithIdRequirement =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesEaxParameters.Variant.TINK)
            .build();
    assertThat(parametersWithIdRequirement.hasIdRequirement()).isTrue();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesEaxKey.builder()
                .setKeyBytes(SecretBytes.randomBytes(16))
                .setParameters(parametersWithIdRequirement)
                .build());
  }

  @Test
  public void build_keyTooSmall_fails() throws Exception {
    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesEaxParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesEaxKey.builder()
                .setParameters(parameters)
                .setKeyBytes(SecretBytes.randomBytes(16))
                .build());
  }

  @Test
  public void build_keyTooLarge_fails() throws Exception {
    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesEaxParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesEaxKey.builder()
                .setParameters(parameters)
                .setKeyBytes(SecretBytes.randomBytes(32))
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

    AesEaxParameters noPrefixParametersKeySize32 =
        AesEaxParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesEaxParameters.Variant.NO_PREFIX)
            .build();
    AesEaxParameters noPrefixParametersKeySize16 =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesEaxParameters.Variant.NO_PREFIX)
            .build();
    AesEaxParameters noPrefixParametersKeySize32IvSize16 =
        AesEaxParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesEaxParameters.Variant.NO_PREFIX)
            .build();
    AesEaxParameters tinkPrefixParametersKeySize32 =
        AesEaxParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesEaxParameters.Variant.TINK)
            .build();
    AesEaxParameters crunchyPrefixParametersKeySize32 =
        AesEaxParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesEaxParameters.Variant.CRUNCHY)
            .build();
    new KeyTester()
        .addEqualityGroup(
            "No prefix, keyBytes32",
            AesEaxKey.builder()
                .setParameters(noPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .build(),
            // The same key built twice must be equal.
            AesEaxKey.builder()
                .setParameters(noPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .build(),
            // The same key built with a copy of key bytes must be equal.
            AesEaxKey.builder()
                .setParameters(noPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32Copy)
                .build(),
            // Setting id requirement to null is equal to not setting it.
            AesEaxKey.builder()
                .setParameters(noPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .setIdRequirement(null)
                .build())
        // This group checks that keys with different key bytes are not equal.
        .addEqualityGroup(
            "No prefix, newly generated keyBytes32",
            AesEaxKey.builder()
                .setParameters(noPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32Diff)
                .build())
        // This group checks that keys with different IV sizes are not equal.
        .addEqualityGroup(
            "No prefix with IV size 16, keyBytes32",
            AesEaxKey.builder()
                .setParameters(noPrefixParametersKeySize32IvSize16)
                .setKeyBytes(keyBytes32)
                .build())
        // This group checks that keys with different key sizes are not equal.
        .addEqualityGroup(
            "No prefix, keyBytes16",
            AesEaxKey.builder()
                .setParameters(noPrefixParametersKeySize16)
                .setKeyBytes(keyBytes16)
                .build())
        .addEqualityGroup(
            "Tink with key id 1907, keyBytes32",
            AesEaxKey.builder()
                .setParameters(tinkPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .setIdRequirement(1907)
                .build(),
            AesEaxKey.builder()
                .setParameters(tinkPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32Copy)
                .setIdRequirement(1907)
                .build())
        // This group checks that keys with different key ids are not equal.
        .addEqualityGroup(
            "Tink with key id 1908, keyBytes32",
            AesEaxKey.builder()
                .setParameters(tinkPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .setIdRequirement(1908)
                .build())
        // This groups checks that keys with different output prefix types are not equal.
        .addEqualityGroup(
            "Crunchy with key id 1907, keyBytes32",
            AesEaxKey.builder()
                .setParameters(crunchyPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .setIdRequirement(1907)
                .build())
        .doTests();
  }
}
