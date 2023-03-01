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

package com.google.crypto.tink.streamingaead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class AesGcmHkdfStreamingParametersTest {
  @Test
  public void buildParametersAndGetProperties() throws Exception {
    AesGcmHkdfStreamingParameters parameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedAesGcmKeySizeBytes(16)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(19);
    assertThat(parameters.getDerivedAesGcmKeySizeBytes()).isEqualTo(16);
    assertThat(parameters.getCiphertextSegmentSizeBytes()).isEqualTo(1024 * 1024);
    assertThat(parameters.getHkdfHashType())
        .isEqualTo(AesGcmHkdfStreamingParameters.HashType.SHA256);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersVariedValues() throws Exception {
    AesGcmHkdfStreamingParameters parameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(77)
            .setDerivedAesGcmKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024)
            .build();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(77);
    assertThat(parameters.getDerivedAesGcmKeySizeBytes()).isEqualTo(32);
    assertThat(parameters.getCiphertextSegmentSizeBytes()).isEqualTo(3 * 1024 * 1024);
    assertThat(parameters.getHkdfHashType()).isEqualTo(AesGcmHkdfStreamingParameters.HashType.SHA1);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersWithoutSettingKeySize_fails() throws Exception {
    AesGcmHkdfStreamingParameters.Builder builder =
        AesGcmHkdfStreamingParameters.builder()
            .setDerivedAesGcmKeySizeBytes(16)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildParametersWithoutSettingDerivedKeySize_fails() throws Exception {
    AesGcmHkdfStreamingParameters.Builder builder =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildParametersWithoutSettingHashType_fails() throws Exception {
    AesGcmHkdfStreamingParameters.Builder builder =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedAesGcmKeySizeBytes(16)
            .setCiphertextSegmentSizeBytes(1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildParametersWithoutSettingCiphertextSegmentSize_fails() throws Exception {
    AesGcmHkdfStreamingParameters.Builder builder =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedAesGcmKeySizeBytes(16)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void ciphertextSegmentSizeLowerLimit() throws Exception {
    AesGcmHkdfStreamingParameters.Builder builder =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(77)
            .setDerivedAesGcmKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(32 + 24);
    assertThrows(GeneralSecurityException.class, builder::build);

    Object unused =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(77)
            .setDerivedAesGcmKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(32 + 25)
            .build();
  }

  @Test
  public void derivedKeySize_fails() throws Exception {
    AesGcmHkdfStreamingParameters.Builder builder =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(77)
            .setDerivedAesGcmKeySizeBytes(24)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);

    builder =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(77)
            .setDerivedAesGcmKeySizeBytes(17)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);

    builder =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(77)
            .setDerivedAesGcmKeySizeBytes(33)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void keyValueShorterThanDerivedKeySize_fails() throws Exception {
    AesGcmHkdfStreamingParameters.Builder builder =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(31)
            .setDerivedAesGcmKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);

    builder =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(15)
            .setDerivedAesGcmKeySizeBytes(16)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testNotEqualandNotEqualHashCode() throws Exception {
    AesGcmHkdfStreamingParameters parameters1 =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setDerivedAesGcmKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    AesGcmHkdfStreamingParameters parameters2 =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setDerivedAesGcmKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    assertThat(parameters1).isEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());

    // Different KeySizeBytes
    parameters2 =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(36)
            .setDerivedAesGcmKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    // Different DerivedAesGcmKeySizeBytes
    parameters2 =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setDerivedAesGcmKeySizeBytes(16)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    // Different hkdf hash type
    parameters2 =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setDerivedAesGcmKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    // Different ciphertext segment size
    parameters2 =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setDerivedAesGcmKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024 + 1)
            .build();

    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }

  @Test
  @SuppressWarnings("TruthIncompatibleType")
  public void testEqualDifferentClass() throws Exception {
    AesGcmHkdfStreamingParameters parameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setDerivedAesGcmKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();
    assertThat(parameters).isNotEqualTo(XChaCha20Poly1305Parameters.create());
  }
}
