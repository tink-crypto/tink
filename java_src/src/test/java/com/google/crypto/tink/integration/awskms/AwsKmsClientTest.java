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

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();
  }

  @Before
  public void setUp() {
    KmsClientsTestUtil.reset();
  }

  @Test
  public void clientBoundToASingleKey_onlySupportsSpecifiedKeyUri() throws Exception {
    String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String keyUri =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    KmsClient client = new AwsKmsClient(keyUri).withAwsKms(new FakeAwsKms(asList(keyId)));
    assertThat(client.doesSupport(keyUri)).isTrue();

    String modifiedKeyUri = keyUri + "1";
    assertThat(client.doesSupport(modifiedKeyUri)).isFalse();
  }

  @Test
  public void clientNoBoundToKey_supportsAllAwsKeys() throws Exception {
    String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String keyUri =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    KmsClient client = new AwsKmsClient().withAwsKms(new FakeAwsKms(asList(keyId)));
    assertThat(client.doesSupport(keyUri)).isTrue();
    assertThat(client.doesSupport("aws-kms://some-other-key")).isTrue();
  }

  @Test
  public void invalidKeyUri_throws() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> new AwsKmsClient("invalid://key-uri"));
  }

  @Test
  public void clientBoundToKeyUri_getAead_works() throws Exception {
    String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String keyUri =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    KmsClient client = new AwsKmsClient(keyUri).withAwsKms(new FakeAwsKms(asList(keyId)));

    Aead kmsAead = client.getAead(keyUri);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void clientUnboundToKeyUri_getAead_works() throws Exception {
    String kekId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String kekUri =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    KmsClient client = new AwsKmsClient().withAwsKms(new FakeAwsKms(asList(kekId)));
    Aead aead = client.getAead(kekUri);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void clientBoundToKeyUri_createKmsEnvelopeAead_works() throws Exception {
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
  public void getAead_onlyWorksForSupportedKeyUri() throws Exception {
    String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String keyId2 = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890xy";
    String keyUri =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String keyUri2 =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890xy";

    KmsClient client = new AwsKmsClient(keyUri).withAwsKms(new FakeAwsKms(asList(keyId, keyId2)));
    Aead unused = client.getAead(keyUri);
    assertThrows(GeneralSecurityException.class, () -> client.getAead(keyUri2));
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
  public void kmsAeadCannotDecryptCiphertextOfDifferentUri() throws Exception {
    String kekId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String kekId2 = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890xy";
    String kekUri =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String kekUri2 =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890xy";

    KmsClient client = new AwsKmsClient().withAwsKms(new FakeAwsKms(asList(kekId, kekId2)));
    Aead kmsAead = client.getAead(kekUri);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);

    Aead kmsAead2 = client.getAead(kekUri2);
    assertThrows(
        GeneralSecurityException.class, () -> kmsAead2.decrypt(ciphertext, associatedData));
  }

  @Test
  public void kmsAeadCanDecryptCiphertextOfAnyUriIfItIsAnAlias() throws Exception {
    String kekId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String kekUri =
        "aws-kms://arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    String aliasUri = "aws-kms://arn:aws:kms:us-west-2:111122223333:alias/ExampleAlias";

    KmsClient client = new AwsKmsClient().withAwsKms(new FakeAwsKms(asList(kekId)));

    Aead kmsAead = client.getAead(kekUri);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);

    // TODO(b/242678738) This behavior is too general, we should change that.
    Aead aliasKmsAead = client.getAead(aliasUri);
    byte[] decrypted = aliasKmsAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void invalidUri_fails() throws Exception {
    String invalidUri = "aws-kms://@#$%&";

    KmsClient client = new AwsKmsClient().withAwsKms(new FakeAwsKms(asList(invalidUri)));

    assertThrows(IllegalArgumentException.class, () -> client.getAead(invalidUri));
  }
}
