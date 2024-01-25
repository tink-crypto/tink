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

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.aead.AesEaxKey;
import com.google.crypto.tink.aead.AesEaxParameters;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class MutableKeyDerivationRegistryTest {
  private static AesGcmKey insecureCreateAesGcmKeyFromRandomness(
      AesGcmParameters parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return AesGcmKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(Util.readIntoSecretBytes(stream, parameters.getKeySizeBytes(), access))
        .build();
  }

  // A different implementation so that for sure we have !AES_GCM_CREATOR.equals(AES_GCM_CREATOR2);
  private static AesGcmKey insecureCreateAesGcmKeyFromRandomness2(
      AesGcmParameters parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    // Throw away a byte.
    Object unused = Util.readIntoSecretBytes(stream, 1, access);
    return AesGcmKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(Util.readIntoSecretBytes(stream, parameters.getKeySizeBytes(), access))
        .build();
  }

  private static AesEaxKey insecureCreateAesEaxKeyFromRandomness(
      AesEaxParameters parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return AesEaxKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(Util.readIntoSecretBytes(stream, parameters.getKeySizeBytes(), access))
        .build();
  }

  private static final MutableKeyDerivationRegistry.InsecureKeyCreator<AesGcmParameters>
      AES_GCM_CREATOR = MutableKeyDerivationRegistryTest::insecureCreateAesGcmKeyFromRandomness;

  private static final MutableKeyDerivationRegistry.InsecureKeyCreator<AesGcmParameters>
      AES_GCM_CREATOR2 = MutableKeyDerivationRegistryTest::insecureCreateAesGcmKeyFromRandomness2;

  private static final MutableKeyDerivationRegistry.InsecureKeyCreator<AesEaxParameters>
      AES_EAX_CREATOR = MutableKeyDerivationRegistryTest::insecureCreateAesEaxKeyFromRandomness;

  @Test
  public void testBasic_setThenCall() throws Exception {
    MutableKeyDerivationRegistry registry = new MutableKeyDerivationRegistry();
    registry.add(AES_GCM_CREATOR, AesGcmParameters.class);
    byte[] keyMaterial = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    Key result =
        registry.createKeyFromRandomness(
            PredefinedAeadParameters.AES128_GCM,
            new ByteArrayInputStream(keyMaterial),
            123,
            InsecureSecretKeyAccess.get());
    Key expectedKey =
        AesGcmKey.builder()
            .setParameters(PredefinedAeadParameters.AES128_GCM)
            .setIdRequirement(123)
            .setKeyBytes(SecretBytes.copyFrom(keyMaterial, InsecureSecretKeyAccess.get()))
            .build();
    assertTrue(result.equalsKey(expectedKey));
  }

  @Test
  public void testWithTwoElements_setThenCall() throws Exception {
    MutableKeyDerivationRegistry registry = new MutableKeyDerivationRegistry();
    registry.add(AES_EAX_CREATOR, AesEaxParameters.class);
    registry.add(AES_GCM_CREATOR, AesGcmParameters.class);
    byte[] keyMaterial = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    Key result =
        registry.createKeyFromRandomness(
            PredefinedAeadParameters.AES128_GCM,
            new ByteArrayInputStream(keyMaterial),
            123,
            InsecureSecretKeyAccess.get());
    Key expectedKey =
        AesGcmKey.builder()
            .setParameters(PredefinedAeadParameters.AES128_GCM)
            .setIdRequirement(123)
            .setKeyBytes(SecretBytes.copyFrom(keyMaterial, InsecureSecretKeyAccess.get()))
            .build();
    assertTrue(result.equalsKey(expectedKey));
  }

  @Test
  public void testInsertMultipleTimes_works() throws Exception {
    MutableKeyDerivationRegistry registry = new MutableKeyDerivationRegistry();
    registry.add(AES_EAX_CREATOR, AesEaxParameters.class);
    registry.add(AES_GCM_CREATOR, AesGcmParameters.class);
    registry.add(AES_EAX_CREATOR, AesEaxParameters.class);
    registry.add(AES_GCM_CREATOR, AesGcmParameters.class);
  }

  @Test
  public void testInsertDifferentObjectForSameParameters_throws() throws Exception {
    MutableKeyDerivationRegistry registry = new MutableKeyDerivationRegistry();
    registry.add(AES_GCM_CREATOR, AesGcmParameters.class);
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.add(AES_GCM_CREATOR2, AesGcmParameters.class));
  }

  @Test
  public void testNonExistent_throws() throws Exception {
    MutableKeyDerivationRegistry registry = new MutableKeyDerivationRegistry();
    registry.add(AES_EAX_CREATOR, AesEaxParameters.class);
    byte[] keyMaterial = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    assertThrows(
        GeneralSecurityException.class,
        () ->
            registry.createKeyFromRandomness(
                PredefinedAeadParameters.AES128_GCM,
                new ByteArrayInputStream(keyMaterial),
                123,
                InsecureSecretKeyAccess.get()));
  }
}
