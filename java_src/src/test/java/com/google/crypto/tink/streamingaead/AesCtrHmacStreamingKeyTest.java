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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class AesCtrHmacStreamingKeyTest {

  @Test
  public void basicBuild_compareParameters_works() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(14)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();
    SecretBytes bytes = SecretBytes.randomBytes(19);
    AesCtrHmacStreamingKey key = AesCtrHmacStreamingKey.create(parameters, bytes);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getInitialKeyMaterial()).isEqualTo(bytes);
  }

  @Test
  public void build_wrongKeySize_throws() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(14)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();
    SecretBytes bytes = SecretBytes.randomBytes(18);
    assertThrows(
        GeneralSecurityException.class, () -> AesCtrHmacStreamingKey.create(parameters, bytes));
  }

  @Test
  public void testEqualities() throws Exception {
    SecretBytes keyBytes33 = SecretBytes.randomBytes(33);
    SecretBytes keyBytes33Copy =
        SecretBytes.copyFrom(
            keyBytes33.toByteArray(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
    SecretBytes keyBytes33Diff = SecretBytes.randomBytes(33);

    AesCtrHmacStreamingParameters parameters33 =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(33)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(14)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();
    AesCtrHmacStreamingParameters parameters33Copy =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(33)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(14)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();
    AesCtrHmacStreamingParameters parametersDifferentHashType =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(33)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(14)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    new KeyTester()
        .addEqualityGroup(
            "33 byte key",
            AesCtrHmacStreamingKey.create(parameters33, keyBytes33),
            AesCtrHmacStreamingKey.create(parameters33, keyBytes33Copy),
            AesCtrHmacStreamingKey.create(parameters33Copy, keyBytes33))
        .addEqualityGroup(
            "different key",
            AesCtrHmacStreamingKey.create(parameters33, keyBytes33Diff),
            AesCtrHmacStreamingKey.create(parameters33Copy, keyBytes33Diff))
        .addEqualityGroup(
            "different parameters",
            AesCtrHmacStreamingKey.create(parametersDifferentHashType, keyBytes33))
        .doTests();
  }

  @Test
  public void testDifferentKeyTypesEquality_fails() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(33)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(14)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(parameters, SecretBytes.randomBytes(33));

    XChaCha20Poly1305Key xChaCha20Poly1305Key =
        XChaCha20Poly1305Key.create(SecretBytes.randomBytes(32));

    assertThat(key.equalsKey(xChaCha20Poly1305Key)).isFalse();
  }
}
