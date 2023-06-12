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

package com.google.crypto.tink.tinkey;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.mac.PredefinedMacParameters;
import com.google.crypto.tink.testing.TestUtil;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@code CreateKeysetCommand}. */
@RunWith(JUnit4.class)
public class CreateKeysetCommandTest {
  @Test
  public void testCreateCleartext_shouldCreateNewKeyset() throws Exception {
    Path path = Files.createTempDirectory(/* prefix= */ "");
    Path outputFile = Paths.get(path.toString(), "keyset");

    Tinkey.main(
        new String[] {
          "create-keyset", "--key-template", "HMAC_SHA256_128BITTAG", "--out", outputFile.toString()
        });

    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            new String(Files.readAllBytes(outputFile), UTF_8), InsecureSecretKeyAccess.get());

    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getPrimary().getKey().getParameters())
        .isEqualTo(PredefinedMacParameters.HMAC_SHA256_128BITTAG);
  }

  @Test
  public void testCreateCleartext_explicitJson_shouldCreateNewKeyset() throws Exception {
    Path path = Files.createTempDirectory(/* prefix= */ "");
    Path outputFile = Paths.get(path.toString(), "keyset");

    String commandLine =
        String.format(
            "create-keyset --key-template HMAC_SHA256_128BITTAG --out-format json --out %s",
            outputFile.toString());

    Tinkey.main(commandLine.split(" "));

    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            new String(Files.readAllBytes(outputFile), UTF_8), InsecureSecretKeyAccess.get());

    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getPrimary().getKey().getParameters())
        .isEqualTo(PredefinedMacParameters.HMAC_SHA256_128BITTAG);
  }

  @Test
  public void testCreateCleartext_binary_shouldCreateNewKeyset() throws Exception {
    Path path = Files.createTempDirectory(/* prefix= */ "");
    Path outputFile = Paths.get(path.toString(), "keyset");

    String commandLine =
        String.format(
            "create-keyset --key-template HMAC_SHA256_128BITTAG --out-format binary --out %s",
            outputFile);

    Tinkey.main(commandLine.split(" "));

    KeysetHandle handle =
        TinkProtoKeysetFormat.parseKeyset(
            Files.readAllBytes(outputFile), InsecureSecretKeyAccess.get());

    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getPrimary().getKey().getParameters())
        .isEqualTo(PredefinedMacParameters.HMAC_SHA256_128BITTAG);
  }

  @Test
  public void testCreateCleartext_gcp_shouldCreateNewKeyset() throws Exception {
    Path path = Files.createTempDirectory(/* prefix= */ "");
    Path outputFile = Paths.get(path.toString(), "keyset");
    String commandLine =
        String.format(
            "create-keyset --key-template HMAC_SHA256_128BITTAG --out-format binary "
                + "--master-key-uri %s "
                + "--credential %s "
                + "--out %s",
            TestUtil.GCP_KMS_TEST_KEY_URI, TestUtil.SERVICE_ACCOUNT_FILE, outputFile.toString());

    Tinkey.main(commandLine.split(" "));

    Aead masterKeyAead =
        KmsClientsFactory.globalInstance()
            .newClientFor(TestUtil.GCP_KMS_TEST_KEY_URI)
            .withCredentials(TestUtil.SERVICE_ACCOUNT_FILE)
            .getAead(TestUtil.GCP_KMS_TEST_KEY_URI);

    KeysetHandle handle =
        TinkProtoKeysetFormat.parseEncryptedKeyset(
            Files.readAllBytes(outputFile), masterKeyAead, new byte[] {});

    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getPrimary().getKey().getParameters())
        .isEqualTo(PredefinedMacParameters.HMAC_SHA256_128BITTAG);
  }

  @Test
  public void testCreateCleartext_gcp_jsonFormat_shouldCreateNewKeyset() throws Exception {
    Path path = Files.createTempDirectory(/* prefix= */ "");
    Path outputFile = Paths.get(path.toString(), "keyset");
    String commandLine =
        String.format(
            "create-keyset --key-template HMAC_SHA256_128BITTAG --out-format json "
                + "--master-key-uri %s "
                + "--credential %s "
                + "--out %s",
            TestUtil.GCP_KMS_TEST_KEY_URI, TestUtil.SERVICE_ACCOUNT_FILE, outputFile.toString());

    Tinkey.main(commandLine.split(" "));

    Aead masterKeyAead =
        KmsClientsFactory.globalInstance()
            .newClientFor(TestUtil.GCP_KMS_TEST_KEY_URI)
            .withCredentials(TestUtil.SERVICE_ACCOUNT_FILE)
            .getAead(TestUtil.GCP_KMS_TEST_KEY_URI);

    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
            new String(Files.readAllBytes(outputFile), UTF_8), masterKeyAead, new byte[] {});

    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getPrimary().getKey().getParameters())
        .isEqualTo(PredefinedMacParameters.HMAC_SHA256_128BITTAG);
  }

}
