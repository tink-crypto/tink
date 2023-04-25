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
public final class AesCtrHmacAeadKeyTest {
  @Test
  public void buildNoPrefixVariantAndGetProperties() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.hasIdRequirement()).isFalse();
    SecretBytes aesKeyBytes = SecretBytes.randomBytes(16);
    SecretBytes hmacKeyBytes = SecretBytes.randomBytes(16);
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(aesKeyBytes)
            .setHmacKeyBytes(hmacKeyBytes)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getAesKeyBytes()).isEqualTo(aesKeyBytes);
    assertThat(key.getHmacKeyBytes()).isEqualTo(hmacKeyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildTinkVariantAndGetProperties() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    SecretBytes aesKeyBytes = SecretBytes.randomBytes(16);
    SecretBytes hmacKeyBytes = SecretBytes.randomBytes(16);
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(aesKeyBytes)
            .setHmacKeyBytes(hmacKeyBytes)
            .setIdRequirement(0x66AABBCC)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getAesKeyBytes()).isEqualTo(aesKeyBytes);
    assertThat(key.getHmacKeyBytes()).isEqualTo(hmacKeyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void buildCrunchyVariantAndGetProperties() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.CRUNCHY)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    SecretBytes aesKeyBytes = SecretBytes.randomBytes(16);
    SecretBytes hmacKeyBytes = SecretBytes.randomBytes(16);
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(aesKeyBytes)
            .setHmacKeyBytes(hmacKeyBytes)
            .setIdRequirement(0x66AABBCC)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getAesKeyBytes()).isEqualTo(aesKeyBytes);
    assertThat(key.getHmacKeyBytes()).isEqualTo(hmacKeyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0066AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void emptyBuild_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> AesCtrHmacAeadKey.builder().build());
  }

  @Test
  public void buildWithoutParameters_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadKey.builder()
                .setAesKeyBytes(SecretBytes.randomBytes(32))
                .setHmacKeyBytes(SecretBytes.randomBytes(32))
                .build());
  }

  @Test
  public void buildWithoutKeyBytes_fails() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCtrHmacAeadKey.builder().setParameters(parameters).build());
  }

  @Test
  public void paramtersRequireIdButIdIsNotSetInBuild_fails() throws Exception {
    AesCtrHmacAeadParameters parametersWithIdRequirement =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    assertThat(parametersWithIdRequirement.hasIdRequirement()).isTrue();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadKey.builder()
                .setAesKeyBytes(SecretBytes.randomBytes(16))
                .setHmacKeyBytes(SecretBytes.randomBytes(16))
                .setParameters(parametersWithIdRequirement)
                .build());
  }

  @Test
  public void paramtersDoesNotRequireIdButIdIsSetInBuild_fails() throws Exception {
    AesCtrHmacAeadParameters parametersWithoutIdRequirement =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parametersWithoutIdRequirement.hasIdRequirement()).isFalse();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadKey.builder()
                .setAesKeyBytes(SecretBytes.randomBytes(16))
                .setHmacKeyBytes(SecretBytes.randomBytes(16))
                .setParameters(parametersWithoutIdRequirement)
                .setIdRequirement(0x66AABBCC)
                .build());
  }

  @Test
  public void build_keyTooSmall_fails() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadKey.builder()
                .setParameters(parameters)
                .setAesKeyBytes(SecretBytes.randomBytes(16))
                .setHmacKeyBytes(SecretBytes.randomBytes(16))
                .build());
  }

  @Test
  public void build_keyTooLarge_fails() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadKey.builder()
                .setParameters(parameters)
                .setAesKeyBytes(SecretBytes.randomBytes(32))
                .setHmacKeyBytes(SecretBytes.randomBytes(32))
                .build());
  }

  @Test
  public void testEqualities() throws Exception {
    SecretBytes keyBytes1 = SecretBytes.randomBytes(32);
    SecretBytes keyBytes1Copy =
        SecretBytes.copyFrom(
            keyBytes1.toByteArray(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
    SecretBytes keyBytes2 = SecretBytes.randomBytes(32);
    SecretBytes keyBytes16 = SecretBytes.randomBytes(16);

    AesCtrHmacAeadParameters noPrefixParameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    AesCtrHmacAeadParameters noPrefixParameters16 =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    AesCtrHmacAeadParameters tinkPrefixParameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    AesCtrHmacAeadParameters crunchyPrefixParameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.CRUNCHY)
            .build();
    AesCtrHmacAeadParameters noPrefixParametersSha512 =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA512)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    AesCtrHmacAeadParameters noPrefixParametersIvSize12 =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setIvSizeBytes(12)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    new KeyTester()
        .addEqualityGroup(
            "No prefix, keyBytes1",
            AesCtrHmacAeadKey.builder()
                .setParameters(noPrefixParameters)
                .setAesKeyBytes(keyBytes1)
                .setHmacKeyBytes(keyBytes1)
                .build(),
            // the same key built twice must be equal
            AesCtrHmacAeadKey.builder()
                .setParameters(noPrefixParameters)
                .setAesKeyBytes(keyBytes1)
                .setHmacKeyBytes(keyBytes1)
                .build(),
            // the same key built with a copy of key bytes must be equal
            AesCtrHmacAeadKey.builder()
                .setParameters(noPrefixParameters)
                .setAesKeyBytes(keyBytes1Copy)
                .setHmacKeyBytes(keyBytes1Copy)
                .build(),
            // setting id requirement to null is equal to not setting it
            AesCtrHmacAeadKey.builder()
                .setParameters(noPrefixParameters)
                .setAesKeyBytes(keyBytes1)
                .setHmacKeyBytes(keyBytes1)
                .setIdRequirement(null)
                .build())
        // This 2 groups check that keys with different key bytes are not equal
        .addEqualityGroup(
            "No prefix, different aes key bytes",
            AesCtrHmacAeadKey.builder()
                .setParameters(noPrefixParameters)
                .setAesKeyBytes(keyBytes2)
                .setHmacKeyBytes(keyBytes1)
                .build())
        .addEqualityGroup(
            "No prefix, different hmac key bytes",
            AesCtrHmacAeadKey.builder()
                .setParameters(noPrefixParameters)
                .setAesKeyBytes(keyBytes1)
                .setHmacKeyBytes(keyBytes2)
                .build())
        // This group checks that keys with different parameters are not equal
        .addEqualityGroup(
            "No prefix with SHA512, keyBytes1",
            AesCtrHmacAeadKey.builder()
                .setParameters(noPrefixParametersSha512)
                .setAesKeyBytes(keyBytes1)
                .setHmacKeyBytes(keyBytes1)
                .build())
        .addEqualityGroup(
            "No prefix, keyBytes16",
            AesCtrHmacAeadKey.builder()
                .setParameters(noPrefixParameters16)
                .setAesKeyBytes(keyBytes16)
                .setHmacKeyBytes(keyBytes16)
                .build())
        .addEqualityGroup(
            "Tink with key id 1907, keyBytes1",
            AesCtrHmacAeadKey.builder()
                .setParameters(tinkPrefixParameters)
                .setAesKeyBytes(keyBytes1)
                .setHmacKeyBytes(keyBytes1)
                .setIdRequirement(1907)
                .build(),
            AesCtrHmacAeadKey.builder()
                .setParameters(tinkPrefixParameters)
                .setAesKeyBytes(keyBytes1Copy)
                .setHmacKeyBytes(keyBytes1Copy)
                .setIdRequirement(1907)
                .build())
        .addEqualityGroup(
            "No prefix, IV size 12",
            AesCtrHmacAeadKey.builder()
                .setParameters(noPrefixParametersIvSize12)
                .setAesKeyBytes(keyBytes1)
                .setHmacKeyBytes(keyBytes1)
                .build())
        // This group checks that keys with different key ids are not equal
        .addEqualityGroup(
            "Tink with key id 1908, keyBytes1",
            AesCtrHmacAeadKey.builder()
                .setParameters(tinkPrefixParameters)
                .setAesKeyBytes(keyBytes1)
                .setHmacKeyBytes(keyBytes1)
                .setIdRequirement(1908)
                .build())
        // This group checks that keys with different output prefix types are not equal
        .addEqualityGroup(
            "Crunchy with key id 1907, keyBytes1",
            AesCtrHmacAeadKey.builder()
                .setParameters(crunchyPrefixParameters)
                .setAesKeyBytes(keyBytes1)
                .setHmacKeyBytes(keyBytes1)
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

    AesCtrHmacAeadParameters aesCtrHmacAeadParameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(16)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();

    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    AesGcmKey aesGcmKey =
        AesGcmKey.builder().setParameters(aesGcmParameters).setKeyBytes(keyBytes).build();
    AesCtrHmacAeadKey aesCtrHmacAeadKey =
        AesCtrHmacAeadKey.builder()
            .setParameters(aesCtrHmacAeadParameters)
            .setAesKeyBytes(keyBytes)
            .setHmacKeyBytes(keyBytes)
            .build();

    assertThat(aesCtrHmacAeadKey.equalsKey(aesGcmKey)).isFalse();
  }
}
