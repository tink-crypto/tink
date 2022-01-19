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


import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link KmsEnvelopeAead} */
@RunWith(JUnit4.class)
public final class KmsEnvelopeAeadTest {
  private static final byte[] EMPTY_ADD = new byte[0];

  @Before
  public void setUp() throws GeneralSecurityException {
    AeadConfig.register();
  }

  private Aead generateNewRemoteAead() throws GeneralSecurityException {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(KeyTemplates.get("AES128_EAX"));
    return keysetHandle.getPrimitive(Aead.class);
  }


  @Test
  public void encryptDecrypt_works() throws GeneralSecurityException {
    Aead remoteAead =  this.generateNewRemoteAead();
    KmsEnvelopeAead envAead =
        new KmsEnvelopeAead(
            KeyTemplateProtoConverter.toProto(KeyTemplates.get("AES128_EAX")), remoteAead);
    byte[] plaintext = "helloworld".getBytes(UTF_8);
    byte[] ciphertext = envAead.encrypt(plaintext, EMPTY_ADD);
    assertArrayEquals(plaintext, envAead.decrypt(ciphertext, EMPTY_ADD));
  }


  @Test
  public void encryptDecryptMissingAd_fails() throws GeneralSecurityException {
    Aead remoteAead =  this.generateNewRemoteAead();
    KmsEnvelopeAead envAead =
        new KmsEnvelopeAead(
            KeyTemplateProtoConverter.toProto(KeyTemplates.get("AES128_EAX")), remoteAead);
    byte[] plaintext = "helloworld".getBytes(UTF_8);
    byte[] associatedData = "envelope_ad".getBytes(UTF_8);
    byte[] ciphertext = envAead.encrypt(plaintext, associatedData);
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
        GeneralSecurityException.class, () -> envAead.decrypt(corruptedCiphertext, EMPTY_ADD));
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
        GeneralSecurityException.class, () -> envAead.decrypt(corruptedCiphertext, EMPTY_ADD));
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



