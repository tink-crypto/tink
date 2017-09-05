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
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.protobuf.TextFormat;
import java.io.ByteArrayOutputStream;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@code CreateKeyTemplateCommand}.
 */
@RunWith(JUnit4.class)
public class CreateKeyTemplateCommandTest {
  @BeforeClass
  public static void setUp() throws Exception {
    Config.register(TinkConfig.TINK_1_0_0);
  }

  @Test
  public void testCreate_shouldWork() throws Exception {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CreateKeyTemplateCommand.create(outputStream,
        AeadConfig.AES_GCM_TYPE_URL, "key_size: 16");
    KeyTemplate.Builder builder = KeyTemplate.newBuilder();
    TextFormat.merge(outputStream.toString(), builder);
    KeyTemplate keyTemplate = builder.build();
    AesGcmKeyFormat aesKeyFormat = AesGcmKeyFormat.parseFrom(keyTemplate.getValue());

    assertThat(keyTemplate.getTypeUrl()).isEqualTo(AeadConfig.AES_GCM_TYPE_URL);
    assertThat(aesKeyFormat.getKeySize()).isEqualTo(16);
  }

  @Test
  public void testCreate_invalidKeySize_shouldThrowException() throws Exception {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    try {
      CreateKeyTemplateCommand.create(outputStream, AeadConfig.AES_GCM_TYPE_URL, "key_size: 17");
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertThat(e.toString()).contains("invalid type URL or key format");
    }
  }

  @Test
  public void testCreate_invalidTypeUrl_shouldThrowException() throws Exception {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    try {
      CreateKeyTemplateCommand.create(outputStream, "bogus", "key_size: 16");
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertThat(e.toString()).contains("invalid type URL or key format");
    }
  }
}
