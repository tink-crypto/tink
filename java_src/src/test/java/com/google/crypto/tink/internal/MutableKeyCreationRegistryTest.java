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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.aead.AesEaxKey;
import com.google.crypto.tink.aead.AesEaxParameters;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.aead.internal.LegacyAesCtrHmacTestKeyManager;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.Set;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class MutableKeyCreationRegistryTest {
  private static AesGcmKey createAesGcmKey(
      AesGcmParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    return AesGcmKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .build();
  }

  // A different implementation so that for sure we have !AES_GCM_CREATOR.equals(AES_GCM_CREATOR2);
  private static AesGcmKey createAesGcmKey2(
      AesGcmParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    // To make the code different from createAesGcmKey2
    Object unused = SecretBytes.randomBytes(1);
    return AesGcmKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .build();
  }

  private static AesEaxKey createAesEaxKey(
      AesEaxParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    return AesEaxKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .build();
  }

  private static final MutableKeyCreationRegistry.KeyCreator<AesGcmParameters> AES_GCM_CREATOR =
      MutableKeyCreationRegistryTest::createAesGcmKey;

  private static final MutableKeyCreationRegistry.KeyCreator<AesGcmParameters> AES_GCM_CREATOR2 =
      MutableKeyCreationRegistryTest::createAesGcmKey2;

  private static final MutableKeyCreationRegistry.KeyCreator<AesEaxParameters> AES_EAX_CREATOR =
      MutableKeyCreationRegistryTest::createAesEaxKey;

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    LegacyAesCtrHmacTestKeyManager.register();
  }

  @Test
  public void testBasic_setThenCall() throws Exception {
    MutableKeyCreationRegistry registry = new MutableKeyCreationRegistry();
    registry.add(AES_GCM_CREATOR, AesGcmParameters.class);

    Key result = registry.createKey(PredefinedAeadParameters.AES128_GCM, 123);
    assertThat(result.getParameters()).isEqualTo(PredefinedAeadParameters.AES128_GCM);
    assertThat(result.getIdRequirementOrNull()).isEqualTo(123);
  }

  @Test
  public void testWithTwoElements_setThenCall() throws Exception {
    MutableKeyCreationRegistry registry = new MutableKeyCreationRegistry();
    registry.add(AES_EAX_CREATOR, AesEaxParameters.class);
    registry.add(AES_GCM_CREATOR, AesGcmParameters.class);

    Key result = registry.createKey(PredefinedAeadParameters.AES128_GCM, 123);
    assertThat(result.getParameters()).isEqualTo(PredefinedAeadParameters.AES128_GCM);
    assertThat(result.getIdRequirementOrNull()).isEqualTo(123);
  }

  @Test
  public void testInsertMultipleTimes_works() throws Exception {
    MutableKeyCreationRegistry registry = new MutableKeyCreationRegistry();
    registry.add(AES_EAX_CREATOR, AesEaxParameters.class);
    registry.add(AES_GCM_CREATOR, AesGcmParameters.class);
    registry.add(AES_EAX_CREATOR, AesEaxParameters.class);
    registry.add(AES_GCM_CREATOR, AesGcmParameters.class);
  }

  @Test
  public void testInsertDifferentObjectForSameParameters_throws() throws Exception {
    MutableKeyCreationRegistry registry = new MutableKeyCreationRegistry();
    registry.add(AES_GCM_CREATOR, AesGcmParameters.class);
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.add(AES_GCM_CREATOR2, AesGcmParameters.class));
  }

  @Test
  public void testNonExistent_throws() throws Exception {
    MutableKeyCreationRegistry registry = new MutableKeyCreationRegistry();
    registry.add(AES_EAX_CREATOR, AesEaxParameters.class);

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.createKey(PredefinedAeadParameters.AES128_GCM, 123));
  }

  @Test
  public void testNotAlwaysTheSameKey() throws Exception {
    Set<Bytes> keyMaterialSet = new HashSet<>();
    MutableKeyCreationRegistry registry = new MutableKeyCreationRegistry();
    registry.add(AES_GCM_CREATOR, AesGcmParameters.class);
    final int numCalls = 100;
    for (int i = 0; i < numCalls; i++) {
      Key result = registry.createKey(PredefinedAeadParameters.AES128_GCM, 123);
      assertThat(result.getParameters()).isEqualTo(PredefinedAeadParameters.AES128_GCM);
      assertThat(result.getIdRequirementOrNull()).isEqualTo(123);
      SecretBytes secretBytes = ((AesGcmKey) result).getKeyBytes();
      Bytes secretBytesAsBytes =
          Bytes.copyFrom(secretBytes.toByteArray(InsecureSecretKeyAccess.get()));
      keyMaterialSet.add(secretBytesAsBytes);
    }
    assertThat(keyMaterialSet).hasSize(numCalls);
  }

  @Test
  public void globalInstanceCanCreateLegacyKeyManagerKeys() throws Exception {
    Parameters legacyAesCtrHmacParameters =
        TinkProtoParametersFormat.parse(
            LegacyAesCtrHmacTestKeyManager.templateWithTinkPrefix().toByteArray());
    Key key =
        MutableKeyCreationRegistry.globalInstance().createKey(legacyAesCtrHmacParameters, 123);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(123);
    assertThat(key.getParameters().toString()).isEqualTo(legacyAesCtrHmacParameters.toString());
  }
}
