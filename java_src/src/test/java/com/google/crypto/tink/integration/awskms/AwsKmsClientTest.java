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

package com.google.crypto.tink.integration.awskms;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.KmsClientsTestUtil;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.KmsAeadKeyManager;
import com.google.crypto.tink.aead.KmsEnvelopeAeadKeyManager;
import java.security.GeneralSecurityException;
import java.util.Optional;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for AwsKmsClient. */
@RunWith(JUnit4.class)
public final class AwsKmsClientTest {
  private static final String CREDENTIAL_FILE_PATH =
      "testdata/aws/credentials.cred";

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();
  }

  @Before
  public void setUp() {
    KmsClientsTestUtil.reset();
  }

  @Test
  public void registerWithKeyUriAndCredentials_success() throws Exception {
    // Register a client bound to a single key.
    String keyUri = "aws-kms://register";
    AwsKmsClient.register(Optional.of(keyUri), Optional.of(CREDENTIAL_FILE_PATH));

    KmsClient client = KmsClients.get(keyUri);
    assertThat(client.doesSupport(keyUri)).isTrue();

    String modifiedKeyUri = keyUri + "1";
    assertThat(client.doesSupport(modifiedKeyUri)).isFalse();
  }

  @Test
  public void registerOnlyWithCredentials_success() throws Exception {
    // Register a client that is not bound to a key URI.
    AwsKmsClient.register(Optional.empty(), Optional.of(CREDENTIAL_FILE_PATH));

    // This should return the above client that should work with any aws-kms key URI.
    String keyUri = "aws-kms://register-unbound";
    KmsClient client = KmsClients.get(keyUri);
    assertThat(client.doesSupport(keyUri)).isTrue();

    String modifiedKeyUri = keyUri + "1";
    assertThat(client.doesSupport(modifiedKeyUri)).isTrue();
  }

  @Test
  public void registerWithCredentialsAndBadKeyUri_fail() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> AwsKmsClient.register(Optional.of("blah"), Optional.of(CREDENTIAL_FILE_PATH)));
  }

  @Test
  public void registerWithKeyUriAndFakeAwsKms_kmsAeadWorks() throws Exception {
    String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String keyUri =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    // Register a client bound to a single key.
    AwsKmsClient.registerWithAwsKms(
        Optional.of(keyUri), Optional.empty(), new FakeAwsKms(asList(keyId)));

    // Create a KmsAead primitive
    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(keyUri);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead kmsAead = handle.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void registerWithKeyUriAndFakeAwsKms_kmsEnvelopeAeadWorks() throws Exception {
    String kekId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String kekUri =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    // Register a client bound to a single key.
    AwsKmsClient.registerWithAwsKms(
        Optional.of(kekUri), Optional.empty(), new FakeAwsKms(asList(kekId)));

    // Create an envelope encryption AEAD primitive
    KeyTemplate dekTemplate = KeyTemplates.get("AES128_CTR_HMAC_SHA256_RAW");
    KeyTemplate envelopeTemplate = KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, dekTemplate);
    KeysetHandle handle = KeysetHandle.generateNew(envelopeTemplate);
    Aead kmsEnvelopeAead = handle.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsEnvelopeAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsEnvelopeAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void registerWithKeyUriAndFakeAwsKms_kmsAeadCanOnlyBeCreatedForRegisteredKeyUri()
      throws Exception {
    String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String keyId2 = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890xy";
    String keyUri =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String keyUri2 =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890xy";

    AwsKmsClient.registerWithAwsKms(
        Optional.of(keyUri), Optional.empty(), new FakeAwsKms(asList(keyId, keyId2)));

    // getPrimitive works for keyUri
    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(keyUri);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead unused = handle.getPrimitive(Aead.class);

    // getPrimitive does not work for keyUri2
    KeyTemplate kmsTemplate2 = KmsAeadKeyManager.createKeyTemplate(keyUri2);
    KeysetHandle handle2 = KeysetHandle.generateNew(kmsTemplate2);
    assertThrows(GeneralSecurityException.class, () -> handle2.getPrimitive(Aead.class));
  }

  @Test
  public void registerBoundWithFakeAwsKms_kmsEnvelopeAeadCanOnlyBeCreatedForBoundedUri()
      throws Exception {
    String kekId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String kekId2 = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890xy";
    String kekUri =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String kekUri2 =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890xy";

    AwsKmsClient.registerWithAwsKms(
        Optional.of(kekUri), Optional.empty(), new FakeAwsKms(asList(kekId, kekId2)));

    KeyTemplate dekTemplate = KeyTemplates.get("AES128_CTR_HMAC_SHA256_RAW");
    // getPrimitive works for kekUri
    KeyTemplate envelopeTemplate = KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, dekTemplate);
    KeysetHandle handle = KeysetHandle.generateNew(envelopeTemplate);
    Aead unused = handle.getPrimitive(Aead.class);

    // getPrimitive does not work for kekUri2
    KeyTemplate envelopeTemplate2 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri2, dekTemplate);
    KeysetHandle handle2 = KeysetHandle.generateNew(envelopeTemplate2);
    assertThrows(GeneralSecurityException.class, () -> handle2.getPrimitive(Aead.class));
  }

  @Test
  public void registerTwoBoundWithFakeAwsKms_kmsAeadWorks() throws Exception {
    String kekId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String kekId2 = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890xy";
    String kekUri =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String kekUri2 =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890xy";

    FakeAwsKms fakeKms = new FakeAwsKms(asList(kekId, kekId2));
    AwsKmsClient.registerWithAwsKms(Optional.of(kekUri), Optional.empty(), fakeKms);
    AwsKmsClient.registerWithAwsKms(Optional.of(kekUri2), Optional.empty(), fakeKms);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(kekUri);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead kmsAead = handle.getPrimitive(Aead.class);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);

    KeyTemplate kmsTemplate2 = KmsAeadKeyManager.createKeyTemplate(kekUri2);
    KeysetHandle handle2 = KeysetHandle.generateNew(kmsTemplate2);
    Aead kmsAead2 = handle2.getPrimitive(Aead.class);
    byte[] ciphertext2 = kmsAead2.encrypt(plaintext, associatedData);
    byte[] decrypted2 = kmsAead2.decrypt(ciphertext2, associatedData);
    assertThat(decrypted2).isEqualTo(plaintext);
  }

  @Test
  public void registerUnboundWithFakeAwsKms_kmsAeadWorks() throws Exception {
    String kekId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String kekUri =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    AwsKmsClient.registerWithAwsKms(
        Optional.empty(), Optional.empty(), new FakeAwsKms(asList(kekId)));

    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(kekUri);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead aead = handle.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void kmsAeadCannotDecryptCiphertextOfDifferentUri() throws Exception {
    String kekId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String kekId2 = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890xy";
    String kekUri =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String kekUri2 =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890xy";

    AwsKmsClient.registerWithAwsKms(
        Optional.empty(), Optional.empty(), new FakeAwsKms(asList(kekId, kekId2)));

    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(kekUri);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead kmsAead = handle.getPrimitive(Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);

    KeyTemplate kmsTemplate2 = KmsAeadKeyManager.createKeyTemplate(kekUri2);
    KeysetHandle handle2 = KeysetHandle.generateNew(kmsTemplate2);
    Aead kmsAead2 = handle2.getPrimitive(Aead.class);
    assertThrows(
        GeneralSecurityException.class, () -> kmsAead2.decrypt(ciphertext, associatedData));
  }

  @Test
  public void kmsAeadCanDecryptCiphertextOfAnyUriIfItIsAnAlias() throws Exception {
    String kekId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String kekUri =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String aliasUri = "aws-kms://arn:aws:kms:us-west-2:111122223333:alias/ExampleAlias";

    AwsKmsClient.registerWithAwsKms(
        Optional.empty(), Optional.empty(), new FakeAwsKms(asList(kekId)));

    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(kekUri);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead kmsAead = handle.getPrimitive(Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);

    // TODO(b/242678738) This behavior is too general, we should change that.
    KeyTemplate aliasKmsTemplate = KmsAeadKeyManager.createKeyTemplate(aliasUri);
    KeysetHandle aliasHandle = KeysetHandle.generateNew(aliasKmsTemplate);
    Aead aliasKmsAead = aliasHandle.getPrimitive(Aead.class);
    byte[] decrypted = aliasKmsAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void invalidUri_fails() throws Exception {
    String invalidUri = "aws-kms://@#$%&";

    AwsKmsClient.registerWithAwsKms(
        Optional.empty(), Optional.empty(), new FakeAwsKms(asList(invalidUri)));

    KeyTemplate template = KmsAeadKeyManager.createKeyTemplate(invalidUri);
    KeysetHandle handle = KeysetHandle.generateNew(template);
    assertThrows(IllegalArgumentException.class, () -> handle.getPrimitive(Aead.class));
  }
}
