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

package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class HkdfPrfKeyTest {

  private static final Bytes SALT = Bytes.copyFrom(TestUtil.hexDecode("2023af"));
  private static HkdfPrfParameters parameters16;

  @BeforeClass
  public static void setUpParameters() throws Exception {
    parameters16 =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .setSalt(SALT)
            .build();
  }

  @DataPoints("keySizes")
  public static final int[] KEY_SIZES = new int[] {16, 32};

  @Theory
  public void build_succeeds(@FromDataPoints("keySizes") int keySize) throws Exception {
    HkdfPrfParameters parameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(keySize)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .setSalt(SALT)
            .build();
    Object unused =
        HkdfPrfKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(keySize))
            .build();
  }

  @Test
  public void buildWithoutSettingParameters_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> HkdfPrfKey.builder().setKeyBytes(SecretBytes.randomBytes(16)).build());
  }

  @Test
  public void buildWithoutSettingKeyBytes_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> HkdfPrfKey.builder().setParameters(parameters16).build());
  }

  @Test
  public void buildWithKeySizeMismatch_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HkdfPrfKey.builder()
                .setParameters(parameters16)
                .setKeyBytes(SecretBytes.randomBytes(32))
                .build());
  }

  @Test
  public void getKeyBytes() throws Exception {
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    assertThat(
            HkdfPrfKey.builder()
                .setParameters(parameters16)
                .setKeyBytes(keyBytes)
                .build()
                .getKeyBytes())
        .isEqualTo(keyBytes);
  }

  @Test
  public void getParameters() throws Exception {
    assertThat(
            HkdfPrfKey.builder()
                .setParameters(parameters16)
                .setKeyBytes(SecretBytes.randomBytes(16))
                .build()
                .getParameters())
        .isEqualTo(parameters16);
  }

  @Test
  public void getIdRequirementOrNull() throws Exception {
    assertThat(
            HkdfPrfKey.builder()
                .setParameters(parameters16)
                .setKeyBytes(SecretBytes.randomBytes(16))
                .build()
                .getIdRequirementOrNull())
        .isNull();
  }

  @Test
  public void equals() throws Exception {
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    SecretBytes keyBytesCopy =
        SecretBytes.copyFrom(
            keyBytes.toByteArray(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
    HkdfPrfParameters parameters32 =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .setSalt(SALT)
            .build();

    new KeyTester()
        .addEqualityGroup(
            "16-byte set key bytes",
            HkdfPrfKey.builder().setParameters(parameters16).setKeyBytes(keyBytes).build(),
            HkdfPrfKey.builder().setParameters(parameters16).setKeyBytes(keyBytesCopy).build())
        .addEqualityGroup(
            "16-byte random key bytes",
            HkdfPrfKey.builder()
                .setParameters(parameters16)
                .setKeyBytes(SecretBytes.randomBytes(16))
                .build())
        .addEqualityGroup(
            "32-byte random key bytes",
            HkdfPrfKey.builder()
                .setParameters(parameters32)
                .setKeyBytes(SecretBytes.randomBytes(32))
                .build())
        .addEqualityGroup(
            "different key class",
            HmacKey.builder()
                .setParameters(
                    HmacParameters.builder()
                        .setKeySizeBytes(16)
                        .setTagSizeBytes(10)
                        .setHashType(HmacParameters.HashType.SHA256)
                        .setVariant(HmacParameters.Variant.NO_PREFIX)
                        .build())
                .setKeyBytes(SecretBytes.randomBytes(16))
                .build())
        .doTests();
  }
}
