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

package com.google.crypto.tink.tinkey;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class TinkeyTestKmsClientTest {
  @BeforeClass
  public static void setUp() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void test_clientCanBeLoadedWithCredential_works() throws Exception {
    Path directory = Files.createTempDirectory(/* prefix= */ "");
    Path credentialPath = Paths.get(directory.toString(), "credentials");
    Files.write(credentialPath, "VALID CREDENTIALS".getBytes(UTF_8));

    KeysetHandle handle = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);
    String masterKeyUri = TinkeyTestKmsClient.createKeyUri(handle);
    Aead masterKey =
        new TinkeyTestKmsClient().withCredentials(credentialPath.toString()).getAead(masterKeyUri);
    Aead manualMasterKey = handle.getPrimitive(Aead.class);

    byte[] ciphertext = manualMasterKey.encrypt(new byte[] {}, new byte[] {});
    assertThat(masterKey.decrypt(ciphertext, new byte[] {})).isEqualTo(new byte[] {});
  }

  @Test
  public void test_clientAllowsCorrectPrefixes_works() throws Exception {
    assertTrue(new TinkeyTestKmsClient().doesSupport("tinkey-test-kms-client://"));
    assertFalse(new TinkeyTestKmsClient().doesSupport("somethingelse://"));

    assertTrue(TinkeyTestKmsClient.createForPrefix("a").doesSupport("a://"));
    assertFalse(TinkeyTestKmsClient.createForPrefix("a").doesSupport("tinkey-test-kms-client://"));
  }

  @Test
  public void test_clientCannotBeUsedWithWrongCredentials_throws() throws Exception {
    Path directory = Files.createTempDirectory(/* prefix= */ "");
    Path credentialPath = Paths.get(directory.toString(), "credentials");
    Files.write(credentialPath, "these are not valid credentials".getBytes(UTF_8));

    KeysetHandle handle = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);
    String masterKeyUri = TinkeyTestKmsClient.createKeyUri(handle);
    KmsClient client = new TinkeyTestKmsClient().withCredentials(credentialPath.toString());
    assertThrows(GeneralSecurityException.class, () -> client.getAead(masterKeyUri));
  }

  @Test
  public void test_clientCannotBeUsedWithoutCallingWithCredential_throws() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);
    String masterKeyUri = TinkeyTestKmsClient.createKeyUri(handle);
    KmsClient client = new TinkeyTestKmsClient();

    assertThrows(GeneralSecurityException.class, () -> client.getAead(masterKeyUri));
  }

  @Test
  public void test_differentPrefix_works() throws Exception {
    Path directory = Files.createTempDirectory(/* prefix= */ "");
    Path credentialPath = Paths.get(directory.toString(), "credentials");
    Files.write(credentialPath, "VALID CREDENTIALS".getBytes(UTF_8));

    KeysetHandle handle = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);
    String masterKeyUri = TinkeyTestKmsClient.createKeyUri(handle);
    Aead masterKey =
        KmsClients.getAutoLoaded(masterKeyUri)
            .withCredentials(credentialPath.toString())
            .getAead(masterKeyUri);
    Aead manualMasterKey = handle.getPrimitive(Aead.class);

    byte[] ciphertext = manualMasterKey.encrypt(new byte[] {}, new byte[] {});
    assertThat(masterKey.decrypt(ciphertext, new byte[] {})).isEqualTo(new byte[] {});
  }
}
