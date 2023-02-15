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

package com.google.crypto.tink.integration.gcpkms;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.aead.AeadConfig;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class GcpKmsAeadTest {

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void kmsAead_works() throws Exception {
    String keyName = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    FakeCloudKms fakeKms = new FakeCloudKms(asList(keyName));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    Aead kmsAead = new GcpKmsAead(fakeKms, keyName);

    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);

    byte[] associatedData2 = "associatedData2".getBytes(UTF_8);
    assertThrows(
        GeneralSecurityException.class, () -> kmsAead.decrypt(ciphertext, associatedData2));

    ciphertext[7] = (byte) (ciphertext[7] ^ 42);
    assertThrows(GeneralSecurityException.class, () -> kmsAead.decrypt(ciphertext, associatedData));
  }

  @Test
  public void kmsAead_encryptDecryptEmptyString_success() throws Exception {
    String keyName = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    FakeCloudKms fakeKms = new FakeCloudKms(asList(keyName));

    byte[] plaintext = "".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    Aead kmsAead = new GcpKmsAead(fakeKms, keyName);

    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void twoKmsAeads_canOnlyDecryptTheirOwnCiphertext() throws Exception {
    String keyName = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key";
    String keyName2 = "projects/tink-test/locations/global/keyRings/unit-test/cryptoKeys/aead-key2";
    FakeCloudKms fakeKms = new FakeCloudKms(asList(keyName, keyName2));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    Aead kmsAead = new GcpKmsAead(fakeKms, keyName);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);

    Aead kmsAead2 = new GcpKmsAead(fakeKms, keyName2);
    byte[] ciphertext2 = kmsAead2.encrypt(plaintext, associatedData);

    assertThat(kmsAead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
    assertThat(kmsAead2.decrypt(ciphertext2, associatedData)).isEqualTo(plaintext);

    assertThrows(
        GeneralSecurityException.class, () -> kmsAead2.decrypt(ciphertext, associatedData));
    assertThrows(
        GeneralSecurityException.class, () -> kmsAead.decrypt(ciphertext2, associatedData));
  }
}
