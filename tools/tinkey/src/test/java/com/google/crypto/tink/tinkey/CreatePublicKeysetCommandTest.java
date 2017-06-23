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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.Registry;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.GcpKmsAeadKeyManager;
import com.google.crypto.tink.hybrid.EciesAeadHkdfPublicKeyManager;
import com.google.crypto.tink.hybrid.HybridDecryptConfig;
import com.google.crypto.tink.hybrid.HybridEncryptConfig;
import com.google.crypto.tink.hybrid.HybridKeyTemplates;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.signature.PublicKeySignConfig;
import com.google.crypto.tink.signature.PublicKeyVerifyConfig;
import com.google.crypto.tink.subtle.ServiceAccountGcpCredentialFactory;
import com.google.protobuf.TextFormat;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@code CreatePublicKeysetCommand}.
 */
@RunWith(JUnit4.class)
public class CreatePublicKeysetCommandTest {
  @Before
  public void setUp() throws Exception {
    AeadConfig.registerStandardKeyTypes();
    MacConfig.registerStandardKeyTypes();
    HybridDecryptConfig.registerStandardKeyTypes();
    HybridEncryptConfig.registerStandardKeyTypes();
    PublicKeySignConfig.registerStandardKeyTypes();
    PublicKeyVerifyConfig.registerStandardKeyTypes();

    Registry.INSTANCE.registerKeyManager(
        GcpKmsAeadKeyManager.TYPE_URL,
        new GcpKmsAeadKeyManager(
            new ServiceAccountGcpCredentialFactory(TestUtil.SERVICE_ACCOUNT_FILE)));
  }

  @Test
  public void testCreate() throws Exception {
    // Create a keyset that contains a single private key of type EciesAeadHkdfPrivateKey.
    KeyTemplate keyTemplate = HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256;
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    String outFormat = "TEXT";
    String awsKmsMasterKeyValue = null;
    String gcpKmsMasterKeyValue = null;
    File credentialFile = null;
    CreateCommand.create(outputStream, outFormat, credentialFile, keyTemplate,
        gcpKmsMasterKeyValue, awsKmsMasterKeyValue);
    Keyset.Builder builder = Keyset.newBuilder();
    TextFormat.merge(outputStream.toString(), builder);
    Keyset privateKeyset = builder.build();
    KeyData privateKeyData = privateKeyset.getKey(0).getKeyData();
    EciesAeadHkdfPrivateKey privateKey = EciesAeadHkdfPrivateKey.parseFrom(
        privateKeyData.getValue());

    // Create the public keyset.
    ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    String inFormat = "TEXT";
    outputStream.reset();
    CreatePublicKeysetCommand.create(outputStream, outFormat, inputStream, inFormat,
        credentialFile);
    builder = Keyset.newBuilder();
    TextFormat.merge(outputStream.toString(), builder);
    Keyset publicKeyset = builder.build();
    assertEquals(1, publicKeyset.getKeyCount());
    assertEquals(publicKeyset.getPrimaryKeyId(), publicKeyset.getKey(0).getKeyId());
    assertEquals(publicKeyset.getPrimaryKeyId(), privateKeyset.getPrimaryKeyId());

    // Check the public key inside the public keyset.
    assertTrue(publicKeyset.getKey(0).hasKeyData());
    assertEquals(KeyStatusType.ENABLED, publicKeyset.getKey(0).getStatus());
    assertEquals(OutputPrefixType.TINK, publicKeyset.getKey(0).getOutputPrefixType());

    KeyData publicKeyData = publicKeyset.getKey(0).getKeyData();
    assertEquals(EciesAeadHkdfPublicKeyManager.TYPE_URL,
        publicKeyData.getTypeUrl());
    assertEquals(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC, publicKeyData.getKeyMaterialType());
    assertArrayEquals(privateKey.getPublicKey().toByteArray(),
        publicKeyData.getValue().toByteArray());
  }
}
