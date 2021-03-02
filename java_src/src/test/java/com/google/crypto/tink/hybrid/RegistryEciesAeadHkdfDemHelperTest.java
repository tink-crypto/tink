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

package com.google.crypto.tink.hybrid;

import static com.google.crypto.tink.testing.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.daead.DeterministicAeadKeyTemplates;
import com.google.crypto.tink.hybrid.subtle.AeadOrDaead;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.signature.SignatureKeyTemplates;
import com.google.crypto.tink.subtle.Random;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for RegistryEciesAeadHkdfDemHelper. */
@RunWith(JUnit4.class)
public class RegistryEciesAeadHkdfDemHelperTest {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  private KeyTemplate[] keyTemplates;

  @Before
  public void setUp() throws Exception {
    Config.register(AeadConfig.TINK_1_0_0);

    if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
      System.out.println(
          "Unlimited Strength Jurisdiction Policy Files are required"
              + " but not installed. Skip tests with keys larger than 128 bits.");
      keyTemplates =
          new KeyTemplate[] {AeadKeyTemplates.AES128_GCM, AeadKeyTemplates.AES128_CTR_HMAC_SHA256};
    } else {
      keyTemplates =
          new KeyTemplate[] {
            AeadKeyTemplates.AES128_GCM,
            AeadKeyTemplates.AES256_GCM,
            AeadKeyTemplates.AES128_CTR_HMAC_SHA256,
            AeadKeyTemplates.AES256_CTR_HMAC_SHA256,
            DeterministicAeadKeyTemplates.AES256_SIV
          };
    }
  }

  @Test
  public void testConstructorWith128BitCiphers() throws Exception {
    RegistryEciesAeadHkdfDemHelper helper;

    // Supported templates.
    helper = new RegistryEciesAeadHkdfDemHelper(AeadKeyTemplates.AES128_GCM);
    assertEquals(16, helper.getSymmetricKeySizeInBytes());
    helper = new RegistryEciesAeadHkdfDemHelper(AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
    assertEquals(48, helper.getSymmetricKeySizeInBytes());
  }

  @Test
  public void testConstructorWith256BitCiphers() throws Exception {
    if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
      System.out.println(
          "Unlimited Strength Jurisdiction Policy Files are required"
              + " but not installed. Skip tests with keys larger than 128 bits.");
      return;
    }
    // Supported templates.
    RegistryEciesAeadHkdfDemHelper helper =
        new RegistryEciesAeadHkdfDemHelper(AeadKeyTemplates.AES256_GCM);
    assertEquals(32, helper.getSymmetricKeySizeInBytes());
    helper = new RegistryEciesAeadHkdfDemHelper(AeadKeyTemplates.AES256_CTR_HMAC_SHA256);
    assertEquals(64, helper.getSymmetricKeySizeInBytes());
  }

  @Test
  public void testConstructorWithUnsupportedTemplates() throws Exception {
    // Unsupported templates.
    int templateCount = 4;
    KeyTemplate[] templates = new KeyTemplate[templateCount];
    templates[0] = AeadKeyTemplates.AES128_EAX;
    templates[1] = AeadKeyTemplates.AES256_EAX;
    templates[2] = AeadKeyTemplates.CHACHA20_POLY1305;
    templates[3] = SignatureKeyTemplates.ECDSA_P256;
    int count = 0;
    for (final KeyTemplate template : templates) {
      GeneralSecurityException e =
          assertThrows(
              "DEM type not supported, should have thrown exception:\n" + template.toString(),
              GeneralSecurityException.class,
              () -> new RegistryEciesAeadHkdfDemHelper(template));
      assertExceptionContains(e, "unsupported AEAD DEM key type");
      assertExceptionContains(e, template.getTypeUrl());
      count++;
    }
    assertEquals(templateCount, count);

    // An inconsistent template.
    final KeyTemplate template =
        KeyTemplate.newBuilder()
            .setTypeUrl(AeadKeyTemplates.AES128_CTR_HMAC_SHA256.getTypeUrl())
            .setValue(SignatureKeyTemplates.ECDSA_P256.getValue())
            .build();
    assertThrows(
        "Inconsistent template, should have thrown exception:\n" + template.toString(),
        GeneralSecurityException.class,
        () -> new RegistryEciesAeadHkdfDemHelper(template));
  }

  @Test
  public void testGetAead() throws Exception {
    byte[] plaintext = "some plaintext string".getBytes(UTF_8);
    byte[] associatedData = "some associated data".getBytes(UTF_8);
    int count = 0;
    for (KeyTemplate template : keyTemplates) {
      RegistryEciesAeadHkdfDemHelper helper = new RegistryEciesAeadHkdfDemHelper(template);
      byte[] symmetricKey = Random.randBytes(helper.getSymmetricKeySizeInBytes());
      AeadOrDaead aead = helper.getAeadOrDaead(symmetricKey);
      byte[] ciphertext = aead.encrypt(plaintext, associatedData);
      byte[] decrypted = aead.decrypt(ciphertext, associatedData);
      assertArrayEquals(plaintext, decrypted);

      // Try using a symmetric key that is too short.
      final byte[] symmetricKey2 = Random.randBytes(helper.getSymmetricKeySizeInBytes() - 1);
      GeneralSecurityException e =
          assertThrows(
              "Symmetric key too short, should have thrown exception:\n" + template.toString(),
              GeneralSecurityException.class,
              () -> helper.getAeadOrDaead(symmetricKey2));
      assertExceptionContains(e, "incorrect length");

      // Try using a symmetric key that is too long.
      final byte[] symmetricKey3 = Random.randBytes(helper.getSymmetricKeySizeInBytes() + 1);
      e =
          assertThrows(
              "Symmetric key too long, should have thrown exception:\n" + template.toString(),
              GeneralSecurityException.class,
              () -> helper.getAeadOrDaead(symmetricKey3));
      assertExceptionContains(e, "incorrect length");
      count++;
    }
    assertEquals(keyTemplates.length, count);
  }
}
