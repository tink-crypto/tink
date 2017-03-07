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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.AesGcmProto.AesGcmKeyFormat;
import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.cloud.crypto.tink.aead.AeadFactory;
import com.google.cloud.crypto.tink.hybrid.HybridDecryptFactory;
import com.google.cloud.crypto.tink.hybrid.HybridEncryptFactory;
import com.google.cloud.crypto.tink.mac.MacFactory;
import com.google.cloud.crypto.tink.signature.PublicKeySignFactory;
import com.google.cloud.crypto.tink.signature.PublicKeyVerifyFactory;
import com.google.protobuf.TextFormat;
import java.io.ByteArrayOutputStream;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@code CreateKeyTemplateCommand}.
 */
@RunWith(JUnit4.class)
public class CreateKeyTemplateCommandTest {
  @Before
  public void setUp() throws Exception {
    AeadFactory.registerStandardKeyTypes();
    MacFactory.registerStandardKeyTypes();
    HybridDecryptFactory.registerStandardKeyTypes();
    HybridEncryptFactory.registerStandardKeyTypes();
    PublicKeySignFactory.registerStandardKeyTypes();
    PublicKeyVerifyFactory.registerStandardKeyTypes();
  }

  @Test
  public void testCreate() throws Exception {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    String typeUrl = "type.googleapis.com/google.cloud.crypto.tink.AesGcmKey";
    String keyFormat = "key_size: 16";
    CreateKeyTemplateCommand.create(outputStream, typeUrl, keyFormat);

    KeyTemplate.Builder builder = KeyTemplate.newBuilder();
    TextFormat.merge(outputStream.toString(), builder);
    KeyTemplate keyTemplate = builder.build();
    assertEquals(typeUrl, keyTemplate.getTypeUrl());
    AesGcmKeyFormat aesKeyFormat = AesGcmKeyFormat.parseFrom(keyTemplate.getValue());
    assertEquals(16, aesKeyFormat.getKeySize());
  }

  @Test
  public void testCreateInvalid() throws Exception {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    String typeUrl = "type.googleapis.com/google.cloud.crypto.tink.AesGcmKey";
    String keyFormat = "key_size: 17";
    try {
      CreateKeyTemplateCommand.create(outputStream, typeUrl, keyFormat);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      System.out.println(e);
      assertTrue(e.toString().contains("invalid type URL or key format"));
    }

    outputStream.reset();
    typeUrl = "AesGcmKey1";
    keyFormat = "key_size: 16";
    try {
      CreateKeyTemplateCommand.create(outputStream, typeUrl, keyFormat);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      System.out.println(e);
      assertTrue(e.toString().contains("invalid type URL or key format"));
    }
  }
}
