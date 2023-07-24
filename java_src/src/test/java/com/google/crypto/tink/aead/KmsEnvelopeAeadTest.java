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
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.FakeKmsClient;
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

  @DataPoints("dekParameters")
  public static final AeadParameters[] DEK_PARAMETERS =
      new AeadParameters[] {
        PredefinedAeadParameters.AES128_GCM,
        PredefinedAeadParameters.AES256_GCM,
        PredefinedAeadParameters.AES128_EAX,
        PredefinedAeadParameters.AES256_EAX,
        PredefinedAeadParameters.AES128_CTR_HMAC_SHA256,
        PredefinedAeadParameters.AES256_CTR_HMAC_SHA256,
        PredefinedAeadParameters.CHACHA20_POLY1305,
        PredefinedAeadParameters.XCHACHA20_POLY1305,
      };

  @Theory
  public void createEncryptDecrypt_works(
      @FromDataPoints("dekParameters") AeadParameters dekParameters) throws Exception {
    Aead remoteAead = this.generateNewRemoteAead();
    Aead envAead = KmsEnvelopeAead.create(dekParameters, remoteAead);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = envAead.encrypt(plaintext, associatedData);
    assertThat(envAead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);

    assertThat(envAead.decrypt(envAead.encrypt(plaintext, EMPTY_ADD), EMPTY_ADD))
        .isEqualTo(plaintext);
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
  public void legacyConstructorEncryptDecrypt_works(
      @FromDataPoints("tinkDekTemplates") String dekTemplateName) throws Exception {
    Aead remoteAead = this.generateNewRemoteAead();
    Aead envAead =
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
  public void createKeyFormatWithInvalidDekTemplate_fails() throws Exception {
    Aead remoteAead = this.generateNewRemoteAead();
    KeyTemplate invalidDekTemplate = HmacKeyManager.hmacSha256Template();

    assertThrows(
        IllegalArgumentException.class,
        () ->
            new KmsEnvelopeAead(KeyTemplateProtoConverter.toProto(invalidDekTemplate), remoteAead));
  }

  @Test
  public void decryptWithInvalidAssociatedData_fails() throws GeneralSecurityException {
    Aead remoteAead =  this.generateNewRemoteAead();
    Aead envAead = KmsEnvelopeAead.create(PredefinedAeadParameters.AES128_EAX, remoteAead);
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
    Aead envAead = KmsEnvelopeAead.create(PredefinedAeadParameters.AES128_EAX, remoteAead);
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
    Aead envAead = KmsEnvelopeAead.create(PredefinedAeadParameters.AES128_EAX, remoteAead);
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
    Aead envAead = KmsEnvelopeAead.create(PredefinedAeadParameters.AES128_EAX, remoteAead);
    assertThrows(
        GeneralSecurityException.class,
        () -> envAead.decrypt("foo".getBytes(UTF_8), "envelope_ad".getBytes(UTF_8)));
  }

  @Test
  public void malformedDekLength_fails() throws GeneralSecurityException {
    Aead remoteAead =  this.generateNewRemoteAead();
    Aead envAead = KmsEnvelopeAead.create(PredefinedAeadParameters.AES128_EAX, remoteAead);

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

  @Test
  public void create_isCompatibleWithOldConstructor() throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();
    Aead remoteAead = new FakeKmsClient().getAead(kekUri);

    Aead aead1 =
        new KmsEnvelopeAead(
            KeyTemplateProtoConverter.toProto(
                AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template()),
            remoteAead);
    Aead aead2 =
        KmsEnvelopeAead.create(PredefinedAeadParameters.AES128_CTR_HMAC_SHA256, remoteAead);

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    assertThat(aead1.decrypt(aead2.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
    assertThat(aead2.decrypt(aead1.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
  }

  @Test
  public void create_isCompatibleWithKmsEnvelopeAeadKey() throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();
    KeyTemplate dekTemplate = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template();

    // Register kmsClient and create a keyset with a KmsEnvelopeAeadKey key.
    KmsClient kmsClient1 = new FakeKmsClient(kekUri);
    KmsClients.add(kmsClient1);
    KeysetHandle handle1 =
        KeysetHandle.generateNew(KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, dekTemplate));
    Aead aead1 = handle1.getPrimitive(Aead.class);

    // Get Aead object from the kmsClient, and create the envelope AEAD without the registry.
    Aead remoteAead = new FakeKmsClient().getAead(kekUri);
    Aead aead2 =
        KmsEnvelopeAead.create(PredefinedAeadParameters.AES128_CTR_HMAC_SHA256, remoteAead);

    // Check that aead1 and aead2 implement the same primitive
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    assertThat(aead1.decrypt(aead2.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
    assertThat(aead2.decrypt(aead1.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
  }
}



