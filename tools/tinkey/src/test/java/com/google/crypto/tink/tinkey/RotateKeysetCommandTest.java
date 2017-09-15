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
import static org.junit.Assert.fail;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.KeysetReader;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@code RotateKeysetCommand}.
*/
@RunWith(JUnit4.class)
public class RotateKeysetCommandTest {
  private static final KeyTemplate EXISTING_TEMPLATE = MacKeyTemplates.HMAC_SHA256_128BITTAG;
  private static final KeyTemplate NEW_TEMPLATE = MacKeyTemplates.HMAC_SHA256_256BITTAG;
  private static final String OUTPUT_FORMAT = "json";
  private static final String INPUT_FORMAT = "json";

  @BeforeClass
  public static void setUp() throws Exception {
    Config.register(TinkConfig.TINK_1_0_0);
  }

  private KeysetReader addNewKeyToKeyset(String outFormat, InputStream inputStream,
      String inFormat, String masterKeyUri, String credentialPath, KeyTemplate template)
      throws Exception {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    RotateKeysetCommand.rotate(
        outputStream, outFormat,
        inputStream, inFormat,
        masterKeyUri, credentialPath,
        template);
    return TinkeyUtil.createKeysetReader(
        new ByteArrayInputStream(outputStream.toByteArray()), outFormat);
  }

  @Test
  public void testRotateCleartext_shouldAddNewKey() throws Exception {
    // Create an input stream containing a cleartext keyset.
    String masterKeyUri = null;
    String credentialPath = null;
    InputStream inputStream = TinkeyUtil.createKeyset(
        EXISTING_TEMPLATE, INPUT_FORMAT, masterKeyUri, credentialPath);
    // Add a new key to the existing keyset.
    Keyset keyset = addNewKeyToKeyset(OUTPUT_FORMAT, inputStream, INPUT_FORMAT,
        masterKeyUri, credentialPath, NEW_TEMPLATE).read();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(keyset.getKey(1).getKeyId());
    TestUtil.assertHmacKey(EXISTING_TEMPLATE, keyset.getKey(0));
    TestUtil.assertHmacKey(NEW_TEMPLATE, keyset.getKey(1));
  }

  @Test
  public void testRotateCleartext_shouldThrowExceptionIfExistingKeysetIsEmpty() throws Exception {
    InputStream emptyStream = new ByteArrayInputStream(new byte[0]);
    String masterKeyUri = null; // This ensures that the keyset won't be encrypted.
    String credentialPath = null;
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    try {
      RotateKeysetCommand.rotate(
          outputStream, OUTPUT_FORMAT,
          emptyStream, INPUT_FORMAT,
          masterKeyUri, credentialPath, NEW_TEMPLATE);
      fail("Expected IOException");
    } catch (IOException e) {
      // expected
    }
  }

  @Test
  public void testRotateEncrypted_shouldAddNewKey() throws Exception {
    // Create an input stream containing an encrypted keyset.
    String masterKeyUri = TestUtil.RESTRICTED_CRYPTO_KEY_URI;
    String credentialPath = TestUtil.SERVICE_ACCOUNT_FILE;
    InputStream inputStream = TinkeyUtil.createKeyset(
        EXISTING_TEMPLATE, INPUT_FORMAT, masterKeyUri, credentialPath);
    EncryptedKeyset encryptedKeyset = addNewKeyToKeyset(OUTPUT_FORMAT, inputStream,
        INPUT_FORMAT, masterKeyUri, credentialPath, NEW_TEMPLATE).readEncrypted();
    KeysetInfo keysetInfo = encryptedKeyset.getKeysetInfo();

    assertThat(keysetInfo.getKeyInfoCount()).isEqualTo(2);
    assertThat(keysetInfo.getPrimaryKeyId()).isEqualTo(keysetInfo.getKeyInfo(1).getKeyId());
    TestUtil.assertKeyInfo(EXISTING_TEMPLATE, keysetInfo.getKeyInfo(0));
    TestUtil.assertKeyInfo(NEW_TEMPLATE, keysetInfo.getKeyInfo(0));
  }

}
