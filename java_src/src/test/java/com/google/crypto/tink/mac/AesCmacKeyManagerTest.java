// Copyright 2017 Google Inc.
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

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Test for AesCmacKeyManager. */
@RunWith(Theories.class)
public class AesCmacKeyManagerTest {
  @Before
  public void register() throws Exception {
    MacConfig.register();
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager("type.googleapis.com/google.crypto.tink.AesCmacKey", Mac.class))
        .isNotNull();
  }

  @Test
  public void testKeyCreationWorks() throws Exception {
    Parameters validParameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setVariant(AesCmacParameters.Variant.TINK)
            .build();
    assertThat(KeysetHandle.generateNew(validParameters).getAt(0).getKey().getParameters())
        .isEqualTo(validParameters);
  }

  @Test
  public void testKeyCreation_invalidParameters_fails() throws Exception {
    // These parameters can be created but aren't accepted by the key manager.
    Parameters validParameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesCmacParameters.Variant.TINK)
            .build();
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.generateNew(validParameters));
  }

  @Test
  public void testMacCreation_succeeds() throws Exception {
    AesCmacParameters validParameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setVariant(AesCmacParameters.Variant.TINK)
            .build();
    AesCmacKey validKey =
        AesCmacKey.builder()
            .setParameters(validParameters)
            .setAesKeyBytes(SecretBytes.randomBytes(validParameters.getKeySizeBytes()))
            .setIdRequirement(739)
            .build();
    KeysetHandle keyset =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(validKey).makePrimary()).build();
    assertThat(keyset.getPrimitive(Mac.class)).isNotNull();
  }

  @Test
  public void testMacCreation_invalidKey_throws() throws Exception {
    // These parameters can be created but aren't accepted by the key manager.
    AesCmacParameters validParameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesCmacParameters.Variant.TINK)
            .build();
    AesCmacKey validKey =
        AesCmacKey.builder()
            .setParameters(validParameters)
            .setAesKeyBytes(SecretBytes.randomBytes(validParameters.getKeySizeBytes()))
            .setIdRequirement(739)
            .build();
    KeysetHandle keyset =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(validKey).makePrimary()).build();
    assertThrows(GeneralSecurityException.class, () -> keyset.getPrimitive(Mac.class));
  }

  @Test
  public void testChunkedMacCreation_succeeds() throws Exception {
    // These parameters can be created but aren't accepted by the key manager.
    AesCmacParameters validParameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setVariant(AesCmacParameters.Variant.TINK)
            .build();
    AesCmacKey validKey =
        AesCmacKey.builder()
            .setParameters(validParameters)
            .setAesKeyBytes(SecretBytes.randomBytes(validParameters.getKeySizeBytes()))
            .setIdRequirement(1023)
            .build();
    KeysetHandle keyset =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(validKey).makePrimary()).build();
    assertThat(keyset.getPrimitive(ChunkedMac.class)).isNotNull();
  }

  @Test
  public void testChunkedMacCreation_invalidKey_throws() throws Exception {
    // These parameters can be created but aren't accepted by the key manager.
    AesCmacParameters validParameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesCmacParameters.Variant.TINK)
            .build();
    AesCmacKey validKey =
        AesCmacKey.builder()
            .setParameters(validParameters)
            .setAesKeyBytes(SecretBytes.randomBytes(validParameters.getKeySizeBytes()))
            .setIdRequirement(739)
            .build();
    KeysetHandle keyset =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(validKey).makePrimary()).build();
    assertThrows(GeneralSecurityException.class, () -> keyset.getPrimitive(ChunkedMac.class));
  }

  @Test
  public void testAes256CmacTemplate() throws Exception {
    KeyTemplate template = AesCmacKeyManager.aes256CmacTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesCmacParameters.builder()
                .setKeySizeBytes(32)
                .setTagSizeBytes(16)
                .setVariant(AesCmacParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testRawAes256CmacTemplate() throws Exception {
    KeyTemplate template = AesCmacKeyManager.rawAes256CmacTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesCmacParameters.builder()
                .setKeySizeBytes(32)
                .setTagSizeBytes(16)
                .setVariant(AesCmacParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testKeyTemplatesWork() throws Exception {
    Parameters p = AesCmacKeyManager.aes256CmacTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = AesCmacKeyManager.rawAes256CmacTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES = new String[] {"AES256_CMAC", "AES256_CMAC_RAW"};

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }
}
