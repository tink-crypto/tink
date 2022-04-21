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
import static org.junit.Assume.assumeFalse;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.testing.TestUtil;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@code CreateKeysetCommand}.
 */
@RunWith(JUnit4.class)
public class CreateKeysetCommandTest {
  private static KeyTemplate template;

  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();
    template = KeyTemplates.get("HMAC_SHA256_128BITTAG");
  }

  @Test
  public void testCreateCleartext_shouldCreateNewKeyset() throws Exception {
    testCreateCleartext_shouldCreateNewKeyset("json");
    testCreateCleartext_shouldCreateNewKeyset("binary");
  }

  private void testCreateCleartext_shouldCreateNewKeyset(String outFormat)
      throws Exception {
    // Create a cleartext keyset.
    String masterKeyUri = null; // This ensures that the keyset won't be encrypted.
    String credentialPath = null;
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CreateKeysetCommand.create(outputStream, outFormat, masterKeyUri, credentialPath, template);
    Keyset keyset = TinkeyUtil.createKeysetReader(
        new ByteArrayInputStream(outputStream.toByteArray()), outFormat).read();

    assertThat(keyset.getKeyCount()).isEqualTo(1);
    TestUtil.assertHmacKey(template, keyset.getKey(0));
  }

  @Test
  public void testCreateEncrypted_shouldCreateNewKeyset() throws Exception {
    testCreateEncrypted_shouldCreateNewKeyset("json");
    testCreateEncrypted_shouldCreateNewKeyset("binary");
  }

  private void testCreateEncrypted_shouldCreateNewKeyset(
      String outFormat) throws Exception {
    // This test requires KMS/internet access and thus cannot run on RBE.
    assumeFalse(TestUtil.isRemoteBuildExecution());
    // Create an encrypted keyset.
    String masterKeyUri = TestUtil.RESTRICTED_CRYPTO_KEY_URI;
    String credentialPath = "../tink_base/" + TestUtil.SERVICE_ACCOUNT_FILE;
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CreateKeysetCommand.create(outputStream, outFormat, masterKeyUri, credentialPath, template);
    EncryptedKeyset encryptedKeyset = TinkeyUtil
        .createKeysetReader(new ByteArrayInputStream(outputStream.toByteArray()), outFormat)
        .readEncrypted();
    KeysetInfo keysetInfo = encryptedKeyset.getKeysetInfo();

    assertThat(keysetInfo.getKeyInfoCount()).isEqualTo(1);
    TestUtil.assertKeyInfo(template, keysetInfo.getKeyInfo(0));
  }
}
