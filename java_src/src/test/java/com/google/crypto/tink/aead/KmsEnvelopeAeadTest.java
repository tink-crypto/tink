// Copyright 2021 Google LLC
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

package com.google.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for {@link KmsEnvelopeAead} */
@RunWith(Theories.class)
public final class KmsEnvelopeAeadTest {
  private static final byte[] EMPTY_ADD = new byte[0];

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    AeadConfig.register();
  }

  private Aead generateNewRemoteAead() throws GeneralSecurityException {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(KeyTemplates.get("AES128_EAX"));
    return keysetHandle.getPrimitive(Aead.class);
  }

  @DataPoints("tinkDekTemplates")
  public static final String[] TINK_DEK_TEMPLATES =
      new String[] {
        "AES128_GCM",
        "AES256_GCM",
        "AES128_EAX",
        "AES256_EAX",
        "AES128_CTR_HMAC_SHA256",
        "AES256_CTR_HMAC_SHA256",
        "CHACHA20_POLY1305",
        "XCHACHA20_POLY1305",
        "AES128_GCM_RAW",
      };

  @Theory
  public void encryptDecrypt_works(@FromDataPoints("tinkDekTemplates") String dekTemplateName)
      throws Exception {
    Aead remoteAead = this.generateNewRemoteAead();
    KmsEnvelopeAead envAead =
        new KmsEnvelopeAead(
            KeyTemplateProtoConverter.toProto(KeyTemplates.get(dekTemplateName)), remoteAead);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = envAead.encrypt(plaintext, associatedData);
    assertThat(envAead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);

    assertThat(envAead.decrypt(envAead.encrypt(plaintext, EMPTY_ADD), EMPTY_ADD))
        .isEqualTo(plaintext);
  }

  @Test
  public void decryptWithInvalidAssociatedData_fails() throws GeneralSecurityException {
    Aead remoteAead =  this.generateNewRemoteAead();
    KmsEnvelopeAead envAead =
        new KmsEnvelopeAead(
            KeyTemplateProtoConverter.toProto(KeyTemplates.get("AES128_EAX")), remoteAead);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = envAead.encrypt(plaintext, associatedData);
    byte[] invalidAssociatedData = "invalidAssociatedData".getBytes(UTF_8);
    assertThrows(
        GeneralSecurityException.class, () -> envAead.decrypt(ciphertext, invalidAssociatedData));
    assertThrows(GeneralSecurityException.class, () -> envAead.decrypt(ciphertext, EMPTY_ADD));
  }

  @Test
  public void corruptedCiphertext_fails() throws GeneralSecurityException {
    Aead remoteAead =  this.generateNewRemoteAead();
    KmsEnvelopeAead envAead =
        new KmsEnvelopeAead(
            KeyTemplateProtoConverter.toProto(KeyTemplates.get("AES128_EAX")), remoteAead);
    byte[] associatedData = "envelope_ad".getBytes(UTF_8);
    byte[] plaintext = "helloworld".getBytes(UTF_8);
    byte[] ciphertext = envAead.encrypt(plaintext, associatedData);
    ciphertext[ciphertext.length - 1] = (byte) (ciphertext[ciphertext.length - 1] ^ 0x1);
    byte[] corruptedCiphertext = ciphertext;
    assertThrows(
        GeneralSecurityException.class, () -> envAead.decrypt(corruptedCiphertext, associatedData));
  }

  @Test
  public void corruptedDek_fails() throws GeneralSecurityException {
    Aead remoteAead =  this.generateNewRemoteAead();
    KmsEnvelopeAead envAead =
        new KmsEnvelopeAead(
            KeyTemplateProtoConverter.toProto(KeyTemplates.get("AES128_EAX")), remoteAead);
    byte[] plaintext = "helloworld".getBytes(UTF_8);
    byte[] associatedData = "envelope_ad".getBytes(UTF_8);
    byte[] ciphertext = envAead.encrypt(plaintext, associatedData);
    ciphertext[4] = (byte) (ciphertext[4] ^ 0x1);
    byte[] corruptedCiphertext = ciphertext;
    assertThrows(
        GeneralSecurityException.class, () -> envAead.decrypt(corruptedCiphertext, associatedData));
  }

  @Test
  public void ciphertextTooShort_fails() throws GeneralSecurityException {
    Aead remoteAead =  this.generateNewRemoteAead();
    KmsEnvelopeAead envAead =
        new KmsEnvelopeAead(
            KeyTemplateProtoConverter.toProto(KeyTemplates.get("AES128_EAX")), remoteAead);
    assertThrows(
        GeneralSecurityException.class,
        () -> envAead.decrypt("foo".getBytes(UTF_8), "envelope_ad".getBytes(UTF_8)));
  }

  @Test
  public void malformedDekLength_fails() throws GeneralSecurityException {
    Aead remoteAead =  this.generateNewRemoteAead();
    KmsEnvelopeAead envAead =
        new KmsEnvelopeAead(
            KeyTemplateProtoConverter.toProto(KeyTemplates.get("AES128_EAX")), remoteAead);

    byte[] plaintext = "helloworld".getBytes(UTF_8);
    byte[] associatedData = "envelope_ad".getBytes(UTF_8);
    byte[] ciphertext = envAead.encrypt(plaintext, associatedData);
    for (int i = 0; i <= 3; i++) {
      ciphertext[i] = (byte) 0xff;
    }
    byte[] corruptedCiphertext1 = ciphertext;

    assertThrows(
        GeneralSecurityException.class,
        () -> envAead.decrypt(corruptedCiphertext1, associatedData));
    for (int i = 0; i <= 3; i++) {
      ciphertext[i] = 0;
    }
    byte[] corruptedCiphertext2 = ciphertext;

    assertThrows(
        GeneralSecurityException.class,
        () -> envAead.decrypt(corruptedCiphertext2, associatedData));
  }
}



