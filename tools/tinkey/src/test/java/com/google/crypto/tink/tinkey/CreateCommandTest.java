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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetReaders;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.config.Config;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.TextFormat;
import java.io.ByteArrayOutputStream;
import java.io.File;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@code CreateCommand}.
 */
@RunWith(JUnit4.class)
public class CreateCommandTest {
  @BeforeClass
  public static void setUp() throws Exception {
    Config.register(Config.TINK_1_0_0);
  }

  @Test
  public void testCreateCleartextKeyset() throws Exception {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    String typeUrl = AesGcmKeyManager.TYPE_URL;
    String keyFormat = "key_size: 16";
    KeyTemplate keyTemplate = TinkeyUtil.createKeyTemplateFromText(typeUrl, keyFormat);
    String awsKmsMasterKeyValue = null;
    String gcpKmsMasterKeyValue = null;
    File credentialFile = null;

    String outFormat = "TEXT";
    CreateCommand.create(outputStream, outFormat, credentialFile, keyTemplate,
        gcpKmsMasterKeyValue, awsKmsMasterKeyValue);
    Keyset.Builder builder = Keyset.newBuilder();
    TextFormat.merge(outputStream.toString(), builder);
    Keyset keyset = builder.build();
    assertEquals(1, keyset.getKeyCount());
    assertEquals(keyset.getPrimaryKeyId(), keyset.getKey(0).getKeyId());
    assertTrue(keyset.getKey(0).hasKeyData());
    assertEquals(typeUrl, keyset.getKey(0).getKeyData().getTypeUrl());
    assertEquals(KeyStatusType.ENABLED, keyset.getKey(0).getStatus());
    assertEquals(OutputPrefixType.TINK, keyset.getKey(0).getOutputPrefixType());
    AesGcmKey aesGcmKey = AesGcmKey.parseFrom(keyset.getKey(0).getKeyData().getValue());
    assertEquals(16, aesGcmKey.getKeyValue().size());

    outputStream.reset();
    outFormat = "BINARY";
    CreateCommand.create(outputStream, outFormat, credentialFile, keyTemplate,
        gcpKmsMasterKeyValue, awsKmsMasterKeyValue);
    keyset = KeysetReaders.withBytes(outputStream.toByteArray()).read();
    assertEquals(1, keyset.getKeyCount());
    assertEquals(keyset.getPrimaryKeyId(), keyset.getKey(0).getKeyId());
    assertTrue(keyset.getKey(0).hasKeyData());
    assertEquals(typeUrl, keyset.getKey(0).getKeyData().getTypeUrl());
    assertEquals(KeyStatusType.ENABLED, keyset.getKey(0).getStatus());
    assertEquals(OutputPrefixType.TINK, keyset.getKey(0).getOutputPrefixType());
    aesGcmKey = AesGcmKey.parseFrom(keyset.getKey(0).getKeyData().getValue());
    assertEquals(16, aesGcmKey.getKeyValue().size());
  }

  @Test
  public void testCreateEncryptedKeysetWithGcp() throws Exception {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    String typeUrl = AesGcmKeyManager.TYPE_URL;
    String keyFormat = "key_size: 16";
    KeyTemplate keyTemplate = TinkeyUtil.createKeyTemplateFromText(typeUrl, keyFormat);
    String awsKmsMasterKeyValue = null;
    String gcpKmsMasterKeyValue = TestUtil.RESTRICTED_CRYPTO_KEY_URI;
    // This is the service account allowed to access the Google Cloud master key above.
    File credentialFile = new File(TestUtil.SERVICE_ACCOUNT_FILE);

    String outFormat = "TEXT";
    CreateCommand.create(outputStream, outFormat, credentialFile, keyTemplate,
        gcpKmsMasterKeyValue, awsKmsMasterKeyValue);
    EncryptedKeyset.Builder builder = EncryptedKeyset.newBuilder();
    TextFormat.merge(outputStream.toString(), builder);
    EncryptedKeyset encryptedKeyset = builder.build();
    KeysetInfo keysetInfo = encryptedKeyset.getKeysetInfo();
    assertEquals(1, keysetInfo.getKeyInfoCount());
    assertEquals(keysetInfo.getPrimaryKeyId(), keysetInfo.getKeyInfo(0).getKeyId());
    assertEquals(typeUrl, keysetInfo.getKeyInfo(0).getTypeUrl());
    assertEquals(KeyStatusType.ENABLED, keysetInfo.getKeyInfo(0).getStatus());
    assertEquals(OutputPrefixType.TINK, keysetInfo.getKeyInfo(0).getOutputPrefixType());

    outputStream.reset();
    outFormat = "BINARY";
    CreateCommand.create(outputStream, outFormat, credentialFile, keyTemplate,
        gcpKmsMasterKeyValue, awsKmsMasterKeyValue);
    Aead masterKey = KmsClients.getAutoLoaded(gcpKmsMasterKeyValue)
        .withCredentials(credentialFile.getPath())
        .getAead(gcpKmsMasterKeyValue);
    KeysetHandle handle = KeysetHandle.read(
        KeysetReaders.withBytes(outputStream.toByteArray()), masterKey);
    keysetInfo = handle.getKeysetInfo();
    assertEquals(1, keysetInfo.getKeyInfoCount());
    assertEquals(keysetInfo.getPrimaryKeyId(), keysetInfo.getKeyInfo(0).getKeyId());
    assertEquals(typeUrl, keysetInfo.getKeyInfo(0).getTypeUrl());
    assertEquals(KeyStatusType.ENABLED, keysetInfo.getKeyInfo(0).getStatus());
    assertEquals(OutputPrefixType.TINK, keysetInfo.getKeyInfo(0).getOutputPrefixType());
  }

  @Test
  public void testCreateEncryptedKeysetWithAws() throws Exception {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    String typeUrl = AesGcmKeyManager.TYPE_URL;
    String keyFormat = "key_size: 16";
    KeyTemplate keyTemplate = TinkeyUtil.createKeyTemplateFromText(typeUrl, keyFormat);
    String awsKmsMasterKeyValue = "blah";
    String gcpKmsMasterKeyValue = null;
    File credentialFile = null;
    String outFormat = "TEXT";

    try {
      CreateCommand.create(outputStream, outFormat, credentialFile, keyTemplate,
          gcpKmsMasterKeyValue, awsKmsMasterKeyValue);
      fail("Expected Exception");
    } catch (Exception e) {
      assertTrue(e.toString().contains("Not Implemented Yet"));
    }
  }
}
