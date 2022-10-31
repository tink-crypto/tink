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

package com.google.crypto.tink.integration.gcpkms;

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

/** Unit tests for {@link GcpKmsClient}.*/
@RunWith(JUnit4.class)
public final class GcpKmsClientTest {
  private static final String CREDENTIAL_FILE_PATH =
      "testdata/gcp/credential.json";

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
    String keyUri = "gcp-kms://register";
    GcpKmsClient.register(Optional.of(keyUri), Optional.of(CREDENTIAL_FILE_PATH));

    KmsClient client = KmsClients.get(keyUri);
    assertThat(client.doesSupport(keyUri)).isTrue();

    String modifiedKeyUri = keyUri + "1";
    assertThat(client.doesSupport(modifiedKeyUri)).isFalse();
  }

  @Test
  public void registerOnlyWithCredentials_success() throws Exception {
    // Register an unbound client.
    GcpKmsClient.register(Optional.empty(), Optional.of(CREDENTIAL_FILE_PATH));

    // This should return the above unbound client.
    String keyUri = "gcp-kms://register-unbound";
    KmsClient client = KmsClients.get(keyUri);
    assertThat(client.doesSupport(keyUri)).isTrue();

    String modifiedKeyUri = keyUri + "1";
    assertThat(client.doesSupport(modifiedKeyUri)).isTrue();
  }

  @Test
  public void registerWithCredentialsAndBadKeyUri_fail() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> GcpKmsClient.register(Optional.of("blah"), Optional.of(CREDENTIAL_FILE_PATH)));
  }

  @SuppressWarnings("deprecation") // We can't use register because we need to inject a FakeCloudKms
  private void registerGcpKmsClient(FakeCloudKms cloudKms) {
    KmsClients.add(new GcpKmsClient().withCloudKms(cloudKms));
  }

  @SuppressWarnings("deprecation") // We can't use register because we need to inject a FakeCloudKms
  private void registerGcpKmsClient(String keyUri, FakeCloudKms cloudKms) {
    KmsClients.add(new GcpKmsClient(keyUri).withCloudKms(cloudKms));
  }

  @Test
  public void registerWithKeyUriAndFakeCloudKms_kmsAeadWorks() throws Exception {
    String keyId = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    String keyUri =
        "gcp-kms://projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";

    // Register a client bound to a single key.
    registerGcpKmsClient(keyUri, new FakeCloudKms(asList(keyId)));

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
  public void registerWithKeyUriAndFakeCloudKms_kmsEnvelopeAeadWorks() throws Exception {
    String keyId = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    String keyUri =
        "gcp-kms://projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";

    // Register a client bound to a single key.
    registerGcpKmsClient(keyUri, new FakeCloudKms(asList(keyId)));

    // Create an envelope encryption AEAD primitive
    KeyTemplate dekTemplate = KeyTemplates.get("AES128_CTR_HMAC_SHA256_RAW");
    KeyTemplate envelopeTemplate = KmsEnvelopeAeadKeyManager.createKeyTemplate(keyUri, dekTemplate);
    KeysetHandle handle = KeysetHandle.generateNew(envelopeTemplate);
    Aead kmsEnvelopeAead = handle.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsEnvelopeAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsEnvelopeAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void registerWithKeyUriAndFakeCloudKms_kmsAeadCanOnlyBeCreatedForRegisteredKeyUri()
      throws Exception {
    String keyId = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    String keyId2 = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key2";
    String keyUri =
        "gcp-kms://projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    String keyUri2 =
        "gcp-kms://projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key2";

    registerGcpKmsClient(keyUri, new FakeCloudKms(asList(keyId, keyId2)));

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
  public void registerWithKeyUriAndFakeCloudKms_kmsEnvelopeAeadCanOnlyBeCreatedForBoundedUri()
      throws Exception {
    String keyId = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    String keyId2 = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key2";
    String keyUri =
        "gcp-kms://projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    String keyUri2 =
        "gcp-kms://projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key2";

    registerGcpKmsClient(keyUri, new FakeCloudKms(asList(keyId, keyId2)));

    KeyTemplate dekTemplate = KeyTemplates.get("AES128_CTR_HMAC_SHA256_RAW");
    // getPrimitive works for keyUri
    KeyTemplate envelopeTemplate = KmsEnvelopeAeadKeyManager.createKeyTemplate(keyUri, dekTemplate);
    KeysetHandle handle = KeysetHandle.generateNew(envelopeTemplate);
    Aead unused = handle.getPrimitive(Aead.class);

    // getPrimitive does not work for keyUri2
    KeyTemplate envelopeTemplate2 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(keyUri2, dekTemplate);
    KeysetHandle handle2 = KeysetHandle.generateNew(envelopeTemplate2);
    assertThrows(GeneralSecurityException.class, () -> handle2.getPrimitive(Aead.class));
  }

  @Test
  public void registerWithTwoKeyUriAndFakeCloudKms_kmsAeadWorks() throws Exception {
    String keyId = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    String keyId2 = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key2";
    String keyUri =
        "gcp-kms://projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    String keyUri2 =
        "gcp-kms://projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key2";

    FakeCloudKms fakeKms = new FakeCloudKms(asList(keyId, keyId2));
    registerGcpKmsClient(keyUri, fakeKms);
    registerGcpKmsClient(keyUri2, fakeKms);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(keyUri);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead kmsAead = handle.getPrimitive(Aead.class);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);

    KeyTemplate kmsTemplate2 = KmsAeadKeyManager.createKeyTemplate(keyUri2);
    KeysetHandle handle2 = KeysetHandle.generateNew(kmsTemplate2);
    Aead kmsAead2 = handle2.getPrimitive(Aead.class);
    byte[] ciphertext2 = kmsAead2.encrypt(plaintext, associatedData);
    byte[] decrypted2 = kmsAead2.decrypt(ciphertext2, associatedData);
    assertThat(decrypted2).isEqualTo(plaintext);
  }

  @Test
  public void registerWithoutKeyUri_kmsAeadWorks() throws Exception {
    String keyId = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    String keyUri =
        "gcp-kms://projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";

    registerGcpKmsClient(new FakeCloudKms(asList(keyId)));

    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(keyUri);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead aead = handle.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void kmsAead_encryptDecryptEmptyString_success() throws Exception {
    String keyId = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    String keyUri =
        "gcp-kms://projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";

    registerGcpKmsClient(new FakeCloudKms(asList(keyId)));

    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(keyUri);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead aead = handle.getPrimitive(Aead.class);

    byte[] plaintext = "".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void kmsAeadCannotDecryptCiphertextOfDifferentUri() throws Exception {
    String keyId = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    String keyId2 = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key2";
    String keyUri =
        "gcp-kms://projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    String keyUri2 =
        "gcp-kms://projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key2";

    registerGcpKmsClient(new FakeCloudKms(asList(keyId, keyId2)));

    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(keyUri);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead kmsAead = handle.getPrimitive(Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);

    KeyTemplate kmsTemplate2 = KmsAeadKeyManager.createKeyTemplate(keyUri2);
    KeysetHandle handle2 = KeysetHandle.generateNew(kmsTemplate2);
    Aead kmsAead2 = handle2.getPrimitive(Aead.class);
    assertThrows(
        GeneralSecurityException.class, () -> kmsAead2.decrypt(ciphertext, associatedData));
  }

  @Test
  public void kmsAeadCannotDecryptCiphertextOfDifferentUriIfItIsHasAnInvalidUri() throws Exception {
    String keyId = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    String keyUri =
        "gcp-kms://projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    String invalidUri = "gcp-kms://@#$%&";

    registerGcpKmsClient(new FakeCloudKms(asList(keyId)));

    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(keyUri);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead kmsAead = handle.getPrimitive(Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);

    KeyTemplate templateWithInvalidUri = KmsAeadKeyManager.createKeyTemplate(invalidUri);
    KeysetHandle handleWithInvalidUri = KeysetHandle.generateNew(templateWithInvalidUri);
    Aead kmsAeadWithInvalidUri = handleWithInvalidUri.getPrimitive(Aead.class);
    assertThrows(IllegalArgumentException.class,
        () -> kmsAeadWithInvalidUri.decrypt(ciphertext, associatedData));
  }
}
