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

package com.google.cloud.crypto.tink.tinkey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.AesGcmProto.AesGcmKey;
import com.google.cloud.crypto.tink.CleartextKeysetHandle;
import com.google.cloud.crypto.tink.GcpKmsProto.GcpKmsAeadKey;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.KmsEncryptedKeysetHandle;
import com.google.cloud.crypto.tink.Registry;
import com.google.cloud.crypto.tink.TestUtil;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.KeysetInfo;
import com.google.cloud.crypto.tink.TinkProto.KmsEncryptedKeyset;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.aead.AeadFactory;
import com.google.cloud.crypto.tink.aead.GcpKmsAeadKeyManager;
import com.google.cloud.crypto.tink.hybrid.HybridDecryptFactory;
import com.google.cloud.crypto.tink.hybrid.HybridEncryptFactory;
import com.google.cloud.crypto.tink.mac.MacFactory;
import com.google.cloud.crypto.tink.signature.PublicKeySignFactory;
import com.google.cloud.crypto.tink.signature.PublicKeyVerifyFactory;
import com.google.cloud.crypto.tink.subtle.ServiceAccountGcpCredentialFactory;
import com.google.protobuf.TextFormat;
import java.io.ByteArrayOutputStream;
import java.io.File;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@code CreateCommand}.
 */
@RunWith(JUnit4.class)
public class CreateCommandTest {
  @Before
  public void setUp() throws Exception {
    AeadFactory.registerStandardKeyTypes();
    MacFactory.registerStandardKeyTypes();
    HybridDecryptFactory.registerStandardKeyTypes();
    HybridEncryptFactory.registerStandardKeyTypes();
    PublicKeySignFactory.registerStandardKeyTypes();
    PublicKeyVerifyFactory.registerStandardKeyTypes();

    Registry.INSTANCE.registerKeyManager(
        "type.googleapis.com/google.cloud.crypto.tink.GcpKmsAeadKey",
        new GcpKmsAeadKeyManager(
            new ServiceAccountGcpCredentialFactory(TestUtil.SERVICE_ACCOUNT_FILE)));
  }

  @Test
  public void testCreateCleartextKeyset() throws Exception {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    String typeUrl = "type.googleapis.com/google.cloud.crypto.tink.AesGcmKey";
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
    KeysetHandle handle = CleartextKeysetHandle.parseFrom(outputStream.toByteArray());
    keyset = handle.getKeyset();
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
    String typeUrl = "type.googleapis.com/google.cloud.crypto.tink.AesGcmKey";
    String keyFormat = "key_size: 16";
    KeyTemplate keyTemplate = TinkeyUtil.createKeyTemplateFromText(typeUrl, keyFormat);
    String awsKmsMasterKeyValue = null;
    String gcpKmsMasterKeyValue = TestUtil.RESTRICTED_CRYPTO_KEY_URI;
    // This is the service account allowed to access the Google Cloud master key above.
    File credentialFile = TestUtil.SERVICE_ACCOUNT_FILE.get();

    String outFormat = "TEXT";
    CreateCommand.create(outputStream, outFormat, credentialFile, keyTemplate,
        gcpKmsMasterKeyValue, awsKmsMasterKeyValue);
    KmsEncryptedKeyset.Builder builder = KmsEncryptedKeyset.newBuilder();
    TextFormat.merge(outputStream.toString(), builder);
    KmsEncryptedKeyset encryptedKeyset = builder.build();
    KeyData kmsKey = encryptedKeyset.getKmsKey();
    assertEquals("type.googleapis.com/google.cloud.crypto.tink.GcpKmsAeadKey",
        kmsKey.getTypeUrl());
    assertEquals(KeyData.KeyMaterialType.REMOTE, kmsKey.getKeyMaterialType());
    GcpKmsAeadKey cloudKey = GcpKmsAeadKey.parseFrom(kmsKey.getValue());
    assertEquals(gcpKmsMasterKeyValue, cloudKey.getKmsKeyUri());

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

    KeysetHandle handle = KmsEncryptedKeysetHandle.parseFrom(outputStream.toByteArray());
    assertNotNull(handle.getEncryptedKeyset());

    Keyset keyset = handle.getKeyset();
    assertEquals(1, keyset.getKeyCount());
    assertEquals(keyset.getPrimaryKeyId(), keyset.getKey(0).getKeyId());
    assertTrue(keyset.getKey(0).hasKeyData());
    assertEquals(typeUrl, keyset.getKey(0).getKeyData().getTypeUrl());
    assertEquals(KeyStatusType.ENABLED, keyset.getKey(0).getStatus());
    assertEquals(OutputPrefixType.TINK, keyset.getKey(0).getOutputPrefixType());
    AesGcmKey aesGcmKey = AesGcmKey.parseFrom(keyset.getKey(0).getKeyData().getValue());
    assertEquals(16, aesGcmKey.getKeyValue().size());

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
    String typeUrl = "type.googleapis.com/google.cloud.crypto.tink.AesGcmKey";
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
