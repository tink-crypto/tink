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
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class AesCmacKeyTest {
  private static final AesCmacParameters.Variant NO_PREFIX = AesCmacParameters.Variant.NO_PREFIX;
  private static final AesCmacParameters.Variant TINK = AesCmacParameters.Variant.TINK;
  private static final AesCmacParameters.Variant LEGACY = AesCmacParameters.Variant.LEGACY;
  private static final AesCmacParameters.Variant CRUNCHY = AesCmacParameters.Variant.CRUNCHY;

  private static AesCmacParameters tinkParameters16;
  private static AesCmacParameters legacyParameters16;
  private static AesCmacParameters crunchyParameters16;
  private static AesCmacParameters noPrefixParameters16;
  private static AesCmacParameters tinkParameters32;
  private static AesCmacParameters legacyParameters32;
  private static AesCmacParameters crunchyParameters32;
  private static AesCmacParameters noPrefixParameters32;

  @BeforeClass
  public static void setUpParameters() throws Exception {
    tinkParameters16 =
        AesCmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setVariant(TINK)
            .build();
    legacyParameters16 =
        AesCmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setVariant(LEGACY)
            .build();
    crunchyParameters16 =
        AesCmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setVariant(CRUNCHY)
            .build();
    noPrefixParameters16 =
        AesCmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setVariant(NO_PREFIX)
            .build();

    tinkParameters32 =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setVariant(TINK)
            .build();
    legacyParameters32 =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setVariant(LEGACY)
            .build();
    crunchyParameters32 =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setVariant(CRUNCHY)
            .build();
    noPrefixParameters32 =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setVariant(NO_PREFIX)
            .build();
  }

  @Test
  public void build_incompleteBuildsFail() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> AesCmacKey.builder().build());
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.builder().setAesKeyBytes(SecretBytes.randomBytes(32)).build());
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.builder().setParameters(tinkParameters16).build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCmacKey.builder()
                .setAesKeyBytes(SecretBytes.randomBytes(32))
                .setParameters(tinkParameters32)
                .build());
  }

  @Test
  public void build_works() throws Exception {
    Object unused =
        AesCmacKey.builder()
            .setParameters(noPrefixParameters16)
            .setAesKeyBytes(SecretBytes.randomBytes(16))
            .build();
    unused =
        AesCmacKey.builder()
            .setParameters(tinkParameters32)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(1907)
            .build();
  }

  @Test
  public void build_failsOnKeySizeMismatch() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCmacKey.builder()
                .setParameters(noPrefixParameters32)
                .setAesKeyBytes(SecretBytes.randomBytes(16))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCmacKey.builder()
                .setParameters(tinkParameters32)
                .setAesKeyBytes(SecretBytes.randomBytes(16))
                .setIdRequirement(199045)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCmacKey.builder()
                .setParameters(noPrefixParameters16)
                .setAesKeyBytes(SecretBytes.randomBytes(32))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCmacKey.builder()
                .setParameters(tinkParameters16)
                .setAesKeyBytes(SecretBytes.randomBytes(32))
                .setIdRequirement(199045)
                .build());
  }

  @Test
  public void getAesKey() throws Exception {
    SecretBytes aesKey = SecretBytes.randomBytes(32);
    assertThat(
            AesCmacKey.builder()
                .setParameters(noPrefixParameters32)
                .setAesKeyBytes(aesKey)
                .build()
                .getAesKey())
        .isEqualTo(aesKey);
  }

  @Test
  public void getParameters() throws Exception {
    assertThat(
            AesCmacKey.builder()
                .setParameters(noPrefixParameters32)
                .setAesKeyBytes(SecretBytes.randomBytes(32))
                .build()
                .getParameters())
        .isEqualTo(noPrefixParameters32);
    assertThat(
            AesCmacKey.builder()
                .setParameters(tinkParameters16)
                .setAesKeyBytes(SecretBytes.randomBytes(16))
                .setIdRequirement(1907)
                .build()
                .getParameters())
        .isEqualTo(tinkParameters16);
  }

  @Test
  public void getIdRequirement() throws Exception {
    assertThat(
            AesCmacKey.builder()
                .setParameters(noPrefixParameters16)
                .setAesKeyBytes(SecretBytes.randomBytes(16))
                .build()
                .getIdRequirementOrNull())
        .isNull();
    assertThat(
            AesCmacKey.builder()
                .setParameters(tinkParameters32)
                .setAesKeyBytes(SecretBytes.randomBytes(32))
                .setIdRequirement(1907)
                .build()
                .getIdRequirementOrNull())
        .isEqualTo(1907);
  }

  @Test
  public void getOutputPrefix() throws Exception {
    assertThat(
            AesCmacKey.builder()
                .setParameters(noPrefixParameters16)
                .setAesKeyBytes(SecretBytes.randomBytes(16))
                .build()
                .getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(
            AesCmacKey.builder()
                .setParameters(tinkParameters16)
                .setAesKeyBytes(SecretBytes.randomBytes(16))
                .setIdRequirement(0x66AABBCC)
                .build()
                .getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
    assertThat(
            AesCmacKey.builder()
                .setParameters(legacyParameters16)
                .setAesKeyBytes(SecretBytes.randomBytes(16))
                .setIdRequirement(0x66AABBCC)
                .build()
                .getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(Hex.decode("0066AABBCC")));
    assertThat(
            AesCmacKey.builder()
                .setParameters(crunchyParameters16)
                .setAesKeyBytes(SecretBytes.randomBytes(16))
                .setIdRequirement(0x66AABBCC)
                .build()
                .getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(Hex.decode("0066AABBCC")));
  }

  @Test
  public void invalidCreations() throws Exception {
    // Must give ID with IDRequirement
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCmacKey.builder()
                .setParameters(tinkParameters16)
                .setAesKeyBytes(SecretBytes.randomBytes(16))
                .setIdRequirement(null)
                .build());
    // Must not give ID without IDRequirement
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCmacKey.builder()
                .setParameters(noPrefixParameters16)
                .setAesKeyBytes(SecretBytes.randomBytes(16))
                .setIdRequirement(123)
                .build());
  }

  @Test
  public void testEqualities() throws Exception {
    SecretBytes key1 = SecretBytes.randomBytes(32);
    SecretBytes key1Copy =
        SecretBytes.copyFrom(
            key1.toByteArray(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
    SecretBytes key2 = SecretBytes.randomBytes(32);
    SecretBytes key3 = SecretBytes.randomBytes(16);
    SecretBytes key4 = SecretBytes.randomBytes(16);
    new KeyTester()
        .addEqualityGroup(
            "No prefix, key1",
            AesCmacKey.builder().setParameters(noPrefixParameters32).setAesKeyBytes(key1).build(),
            AesCmacKey.builder()
                .setParameters(noPrefixParameters32)
                .setAesKeyBytes(key1)
                .setIdRequirement(null)
                .build())
        .addEqualityGroup(
            "No prefix, key2",
            AesCmacKey.builder().setParameters(noPrefixParameters32).setAesKeyBytes(key2).build(),
            AesCmacKey.builder()
                .setParameters(noPrefixParameters32)
                .setAesKeyBytes(key2)
                .setIdRequirement(null)
                .build())
        .addEqualityGroup(
            "No prefix, key3",
            AesCmacKey.builder().setParameters(noPrefixParameters16).setAesKeyBytes(key3).build(),
            AesCmacKey.builder()
                .setParameters(noPrefixParameters16)
                .setAesKeyBytes(key3)
                .setIdRequirement(null)
                .build())
        .addEqualityGroup(
            "No prefix, key4",
            AesCmacKey.builder().setParameters(noPrefixParameters16).setAesKeyBytes(key4).build(),
            AesCmacKey.builder()
                .setParameters(noPrefixParameters16)
                .setAesKeyBytes(key4)
                .setIdRequirement(null)
                .build())
        .addEqualityGroup(
            "Tink 1907 key1",
            AesCmacKey.builder()
                .setParameters(tinkParameters32)
                .setAesKeyBytes(key1)
                .setIdRequirement(1907)
                .build(),
            AesCmacKey.builder()
                .setParameters(tinkParameters32)
                .setAesKeyBytes(key1)
                .setIdRequirement(1907)
                .build())
        .addEqualityGroup(
            "Tink 1908 key1",
            AesCmacKey.builder()
                .setParameters(tinkParameters32)
                .setAesKeyBytes(key1Copy)
                .setIdRequirement(1908)
                .build(),
            AesCmacKey.builder()
                .setParameters(tinkParameters32)
                .setAesKeyBytes(key1)
                .setIdRequirement(1908)
                .build())
        .addEqualityGroup(
            "Tink 1907 key3",
            AesCmacKey.builder()
                .setParameters(tinkParameters16)
                .setAesKeyBytes(key3)
                .setIdRequirement(1907)
                .build(),
            AesCmacKey.builder()
                .setParameters(tinkParameters16)
                .setAesKeyBytes(key3)
                .setIdRequirement(1907)
                .build())
        .addEqualityGroup(
            "Tink 1908 key3",
            AesCmacKey.builder()
                .setParameters(tinkParameters16)
                .setAesKeyBytes(key3)
                .setIdRequirement(1908)
                .build(),
            AesCmacKey.builder()
                .setParameters(tinkParameters16)
                .setAesKeyBytes(key3)
                .setIdRequirement(1908)
                .build())
        .addEqualityGroup(
            "Legacy 1907 key1",
            AesCmacKey.builder()
                .setParameters(legacyParameters32)
                .setAesKeyBytes(key1)
                .setIdRequirement(1907)
                .build(),
            AesCmacKey.builder()
                .setParameters(legacyParameters32)
                .setAesKeyBytes(key1)
                .setIdRequirement(1907)
                .build())
        .addEqualityGroup(
            "Crunchy 1907 key1",
            AesCmacKey.builder()
                .setParameters(crunchyParameters32)
                .setAesKeyBytes(key1)
                .setIdRequirement(1907)
                .build(),
            AesCmacKey.builder()
                .setParameters(crunchyParameters32)
                .setAesKeyBytes(key1)
                .setIdRequirement(1907)
                .build())
        .addEqualityGroup(
            "Legacy 1907 key3",
            AesCmacKey.builder()
                .setParameters(legacyParameters16)
                .setAesKeyBytes(key3)
                .setIdRequirement(1907)
                .build(),
            AesCmacKey.builder()
                .setParameters(legacyParameters16)
                .setAesKeyBytes(key3)
                .setIdRequirement(1907)
                .build())
        .addEqualityGroup(
            "Crunchy 1907 key3",
            AesCmacKey.builder()
                .setParameters(crunchyParameters16)
                .setAesKeyBytes(key3)
                .setIdRequirement(1907)
                .build(),
            AesCmacKey.builder()
                .setParameters(crunchyParameters16)
                .setAesKeyBytes(key3)
                .setIdRequirement(1907)
                .build())
        .doTests();
  }
}
