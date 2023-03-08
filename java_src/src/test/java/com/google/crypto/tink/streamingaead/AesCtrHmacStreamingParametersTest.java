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
public final class AesCtrHmacStreamingParametersTest {
  @Test
  public void buildParametersAndGetProperties() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(14)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(19);
    assertThat(parameters.getDerivedKeySizeBytes()).isEqualTo(16);
    assertThat(parameters.getHkdfHashType())
        .isEqualTo(AesCtrHmacStreamingParameters.HashType.SHA256);
    assertThat(parameters.getHmacHashType()).isEqualTo(AesCtrHmacStreamingParameters.HashType.SHA1);
    assertThat(parameters.getHmacTagSizeBytes()).isEqualTo(14);
    assertThat(parameters.getCiphertextSegmentSizeBytes()).isEqualTo(1024 * 1024);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersVariedValues() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024)
            .build();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(35);
    assertThat(parameters.getDerivedKeySizeBytes()).isEqualTo(32);
    assertThat(parameters.getHkdfHashType())
        .isEqualTo(AesCtrHmacStreamingParameters.HashType.SHA512);
    assertThat(parameters.getHmacHashType())
        .isEqualTo(AesCtrHmacStreamingParameters.HashType.SHA256);
    assertThat(parameters.getHmacTagSizeBytes()).isEqualTo(16);
    assertThat(parameters.getCiphertextSegmentSizeBytes()).isEqualTo(3 * 1024 * 1024);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParameters_withoutSetKeySize_fails() throws Exception {
    AesCtrHmacStreamingParameters.Builder builder =
        AesCtrHmacStreamingParameters.builder()
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildParameters_withoutSetDerivedKeySize_fails() throws Exception {
    AesCtrHmacStreamingParameters.Builder builder =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildParameters_withoutSetHkdfHashType_fails() throws Exception {
    AesCtrHmacStreamingParameters.Builder builder =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setDerivedKeySizeBytes(32)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildParameters_withoutSetHmacHashType_fails() throws Exception {
    AesCtrHmacStreamingParameters.Builder builder =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildParameters_withoutSetHmacTagSize_fails() throws Exception {
    AesCtrHmacStreamingParameters.Builder builder =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildParameters_withoutSetCiphertextSegmentSize_fails() throws Exception {
    AesCtrHmacStreamingParameters.Builder builder =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(16);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildParameters_derivedKeySizeNot16Or32A_throws() throws Exception {
    AesCtrHmacStreamingParameters.Builder builder =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setDerivedKeySizeBytes(24)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildParameters_derivedKeySizeNot16Or32B_throws() throws Exception {
    AesCtrHmacStreamingParameters.Builder builder =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setDerivedKeySizeBytes(17)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildParameters_ciphertextSegmentSizeLowerBound() throws Exception {
    AesCtrHmacStreamingParameters.Builder builder =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(19)
            .setCiphertextSegmentSizeBytes(32 + 19 + 8);
    assertThrows(GeneralSecurityException.class, builder::build);

    builder.setCiphertextSegmentSizeBytes(32 + 19 + 8 + 1);
    Object unused = builder.build();
  }

  @Test
  public void buildParameters_ciphertextSegmentSizeLowerBound2() throws Exception {
    AesCtrHmacStreamingParameters.Builder builder =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(35)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(19)
            .setCiphertextSegmentSizeBytes(16 + 19 + 8);
    assertThrows(GeneralSecurityException.class, builder::build);

    builder.setCiphertextSegmentSizeBytes(16 + 19 + 8 + 1);
    Object unused = builder.build();
  }

  @Test
  public void buildParameters_initialKeymaterialBound1() throws Exception {
    AesCtrHmacStreamingParameters.Builder builder =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(31)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);

    builder.setKeySizeBytes(32);
    Object unused = builder.build();
  }

  @Test
  public void buildParameters_initialKeymaterialBound2() throws Exception {
    AesCtrHmacStreamingParameters.Builder builder =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(15)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);
    assertThrows(GeneralSecurityException.class, builder::build);

    builder.setKeySizeBytes(16);
    Object unused = builder.build();
  }

  @Test
  public void buildParameters_hmacTagSize_SHA1_bounds() throws Exception {
    AesCtrHmacStreamingParameters.Builder builder =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);

    builder.setHmacTagSizeBytes(9);
    assertThrows(GeneralSecurityException.class, builder::build);

    builder.setHmacTagSizeBytes(10);
    Object unused = builder.build();

    builder.setHmacTagSizeBytes(19);
    unused = builder.build();

    builder.setHmacTagSizeBytes(20);
    unused = builder.build();

    builder.setHmacTagSizeBytes(21);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildParameters_hmacTagSize_SHA256_bounds() throws Exception {
    AesCtrHmacStreamingParameters.Builder builder =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);

    builder.setHmacTagSizeBytes(9);
    assertThrows(GeneralSecurityException.class, builder::build);

    builder.setHmacTagSizeBytes(10);
    Object unused = builder.build();

    builder.setHmacTagSizeBytes(31);
    unused = builder.build();

    builder.setHmacTagSizeBytes(32);
    unused = builder.build();

    builder.setHmacTagSizeBytes(33);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildParameters_hmacTagSize_SHA512_bounds() throws Exception {
    AesCtrHmacStreamingParameters.Builder builder =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024);

    builder.setHmacTagSizeBytes(9);
    assertThrows(GeneralSecurityException.class, builder::build);

    builder.setHmacTagSizeBytes(10);
    Object unused = builder.build();

    builder.setHmacTagSizeBytes(63);
    unused = builder.build();

    builder.setHmacTagSizeBytes(64);
    unused = builder.build();

    builder.setHmacTagSizeBytes(65);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testNotEqualandNotEqualHashCode() throws Exception {
    AesCtrHmacStreamingParameters parameters1 =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(33)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(14)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    AesCtrHmacStreamingParameters parameters2 =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(33)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(14)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    assertThat(parameters1).isEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());

    // Different KeySizeBytes
    parameters2 =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(14)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    // Different DerivedKeySizeBytes
    parameters2 =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(33)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(14)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    // Different HkdfHashType
    parameters2 =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(33)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(14)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    // Different HmacHashType
    parameters2 =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(33)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacTagSizeBytes(14)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    // Different HmacTagSizeBytes
    parameters2 =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(33)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(15)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    // Different CiphertextSegmentSize
    parameters2 =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(33)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(14)
            .setCiphertextSegmentSizeBytes(3 * 1024 * 1024)
            .build();

    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }

  @Test
  @SuppressWarnings("TruthIncompatibleType")
  public void testEqualDifferentClass() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(14)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();
    assertThat(parameters).isNotEqualTo(XChaCha20Poly1305Parameters.create());
  }
}
