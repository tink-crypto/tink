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

package com.google.crypto.tink.keyderivation;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.Util.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplate.OutputPrefixType;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.prf.PrfConfig;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class KeyDerivationKeyTemplatesTest {

  @BeforeClass
  public static void setUp() throws Exception {
    KeyDerivationConfig.register();
    PrfConfig.register();
    AeadConfig.register();
  }

  @Test
  public void createPrfBasedKeyTemplate_succeeds() throws Exception {
    Assume.assumeFalse(TestUtil.isAndroid()); // Some Android versions don't support AES-GCM.

    KeyTemplate prfTemplate = KeyTemplates.get("HKDF_SHA256");
    KeyTemplate aeadTemplate = KeyTemplates.get("AES256_GCM");

    List<OutputPrefixType> outputPrefixTypes = new ArrayList<>();
    outputPrefixTypes.add(OutputPrefixType.TINK);
    outputPrefixTypes.add(OutputPrefixType.LEGACY);
    outputPrefixTypes.add(OutputPrefixType.RAW);
    outputPrefixTypes.add(OutputPrefixType.CRUNCHY);

    for (OutputPrefixType outputPrefixType : outputPrefixTypes) {
      KeyTemplate derivedTemplate =
          KeyTemplate.create(aeadTemplate.getTypeUrl(), aeadTemplate.getValue(), outputPrefixType);
      KeyTemplate prfBasedTemplate =
          KeyDerivationKeyTemplates.createPrfBasedKeyTemplate(prfTemplate, derivedTemplate);

      KeysetHandle handle = KeysetHandle.generateNew(prfBasedTemplate);
      KeysetDeriver deriver = handle.getPrimitive(KeysetDeriver.class);
      KeysetHandle derivedHandle = deriver.deriveKeyset("salty".getBytes(UTF_8));
      assertThat(derivedHandle.getKeysetInfo().getKeyInfoCount()).isEqualTo(1);
      assertThat(derivedHandle.getKeysetInfo().getKeyInfo(0).getOutputPrefixType().toString())
          .isEqualTo(outputPrefixType.toString());

      // Use derivedHandle, which contains an AES256_GCM key.
      Aead aead = derivedHandle.getPrimitive(Aead.class);
      byte[] plaintext = "plaintext".getBytes(UTF_8);
      byte[] associatedData = "associatedData".getBytes(UTF_8);
      byte[] ciphertext = aead.encrypt(plaintext, associatedData);
      assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
    }
  }

  @Test
  public void createPrfBasedKeyTemplate_failsForNotPrf() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            KeyDerivationKeyTemplates.createPrfBasedKeyTemplate(
                KeyTemplates.get("AES256_GCM"), KeyTemplates.get("AES256_GCM")));
  }

  @Test
  public void createPrfBasedKeyTemplate_failsForNotDerivableKeyType() throws Exception {
    KeyTemplate derivedTemplate =
        KeyDerivationKeyTemplates.createPrfBasedKeyTemplate(
            KeyTemplates.get("HKDF_SHA256"), KeyTemplates.get("AES256_GCM"));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            KeyDerivationKeyTemplates.createPrfBasedKeyTemplate(
                KeyTemplates.get("HKDF_SHA256"), derivedTemplate));
  }
}
