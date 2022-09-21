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

package com.google.crypto.tink.mac;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class HmacKeyTest {

  @Test
  public void buildNoPrefixVariantAndGetProperties() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.hasIdRequirement()).isFalse();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    HmacKey key = HmacKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildTinkVariantAndGetProperties() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.TINK)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    HmacKey key =
        HmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setIdRequirement(0x66AABBCC)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(TestUtil.hexDecode("0166AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void buildLegacyVariantAndGetProperties() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.LEGACY)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    HmacKey key =
        HmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setIdRequirement(0x66AABBCC)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(TestUtil.hexDecode("0066AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void buildCrunchyVariantAndGetProperties() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.CRUNCHY)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    HmacKey key =
        HmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setIdRequirement(0x66AABBCC)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(TestUtil.hexDecode("0066AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void emptyBuild_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> HmacKey.builder().build());
  }

  @Test
  public void buildWithoutParameters_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> HmacKey.builder().setKeyBytes(SecretBytes.randomBytes(32)).build());
  }

  @Test
  public void buildWithoutKeyBytes_fails() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class, () -> HmacKey.builder().setParameters(parameters).build());
  }

  @Test
  public void paramtersRequireIdButIdIsNotSetInBuild_fails() throws Exception {
    HmacParameters parametersWithIdRequirement =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.TINK)
            .build();
    assertThat(parametersWithIdRequirement.hasIdRequirement()).isTrue();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacKey.builder()
                .setKeyBytes(SecretBytes.randomBytes(32))
                .setParameters(parametersWithIdRequirement)
                .build());
  }

  @Test
  public void paramtersDoesNotRequireIdButIdIsSetInBuild_fails() throws Exception {
    HmacParameters parametersWithoutIdRequirement =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parametersWithoutIdRequirement.hasIdRequirement()).isFalse();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacKey.builder()
                .setKeyBytes(SecretBytes.randomBytes(32))
                .setParameters(parametersWithoutIdRequirement)
                .setIdRequirement(0x66AABBCC)
                .build());
  }

  @Test
  public void build_keyTooSmall_fails() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacKey.builder()
                .setParameters(parameters)
                .setKeyBytes(SecretBytes.randomBytes(16))
                .build());
  }

  @Test
  public void build_keyTooLarge_fails() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacKey.builder()
                .setParameters(parameters)
                .setKeyBytes(SecretBytes.randomBytes(32))
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

    HmacParameters noPrefixParameters =
        HmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    HmacParameters noPrefixParameters16 =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    HmacParameters tinkPrefixParameters =
        HmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.TINK)
            .build();
    HmacParameters legacyPrefixParameters =
        HmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.LEGACY)
            .build();
    HmacParameters crunchyPrefixParameters =
        HmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.CRUNCHY)
            .build();
    HmacParameters noPrefixParametersSha512 =
        HmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA512)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    new KeyTester()
        .addEqualityGroup(
            "No prefix, keyBytes1",
            HmacKey.builder().setParameters(noPrefixParameters).setKeyBytes(keyBytes1).build(),
            // the same key built twice must be equal
            HmacKey.builder().setParameters(noPrefixParameters).setKeyBytes(keyBytes1).build(),
            // the same key built with a copy of key bytes must be equal
            HmacKey.builder().setParameters(noPrefixParameters).setKeyBytes(keyBytes1Copy).build(),
            // setting id requirement to null is equal to not setting it
            HmacKey.builder()
                .setParameters(noPrefixParameters)
                .setKeyBytes(keyBytes1)
                .setIdRequirement(null)
                .build())
        // This group checks that keys with different key bytes are not equal
        .addEqualityGroup(
            "No prefix, keyBytes2",
            HmacKey.builder().setParameters(noPrefixParameters).setKeyBytes(keyBytes2).build())
        // This group checks that keys with different parameters are not equal
        .addEqualityGroup(
            "No prefix with SHA512, keyBytes1",
            HmacKey.builder()
                .setParameters(noPrefixParametersSha512)
                .setKeyBytes(keyBytes1)
                .build())
        .addEqualityGroup(
            "No prefix, keyBytes16",
            HmacKey.builder().setParameters(noPrefixParameters16).setKeyBytes(keyBytes16).build())
        .addEqualityGroup(
            "Tink with key id 1907, keyBytes1",
            HmacKey.builder()
                .setParameters(tinkPrefixParameters)
                .setKeyBytes(keyBytes1)
                .setIdRequirement(1907)
                .build(),
            HmacKey.builder()
                .setParameters(tinkPrefixParameters)
                .setKeyBytes(keyBytes1)
                .setIdRequirement(1907)
                .build(),
            HmacKey.builder()
                .setParameters(tinkPrefixParameters)
                .setKeyBytes(keyBytes1Copy)
                .setIdRequirement(1907)
                .build())
        // This group checks that keys with different key ids are not equal
        .addEqualityGroup(
            "Tink with key id 1908, keyBytes1",
            HmacKey.builder()
                .setParameters(tinkPrefixParameters)
                .setKeyBytes(keyBytes1)
                .setIdRequirement(1908)
                .build())
        // This 2 groups check that keys with different output prefix types are not equal
        .addEqualityGroup(
            "Legacy with key id 1907, keyBytes1",
            HmacKey.builder()
                .setParameters(legacyPrefixParameters)
                .setKeyBytes(keyBytes1)
                .setIdRequirement(1907)
                .build())
        .addEqualityGroup(
            "Crunchy with key id 1907, keyBytes1",
            HmacKey.builder()
                .setParameters(crunchyPrefixParameters)
                .setKeyBytes(keyBytes1)
                .setIdRequirement(1907)
                .build())
        .doTests();
  }
}
