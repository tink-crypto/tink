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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.fail;

import com.google.crypto.tink.config.Config;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for KeysetManager.
 */
@RunWith(JUnit4.class)
public class KeysetManagerTest {
  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    Config.register(Config.TINK_HYBRID_1_0_0);  // includes TINK_AEAD_1_0_0
  }

  @Test
  public void testRotate_shouldAddNewKeyAndSetPrimaryKeyId() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    Keyset keyset = KeysetManager.withEmptyKeyset()
        .rotate(template)
        .getKeysetHandle()
        .getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(keyset.getKey(0).getKeyId());
    TestUtil.assertHmacKey(template, keyset.getKey(0));
  }

  @Test
  public void testRotate_bogusKeyTemplate_shouldThrowException() throws Exception {
    KeyTemplate bogus = TestUtil.createKeyTemplateWithNonExistingTypeUrl();

    try {
      KeysetManager
          .withEmptyKeyset()
          .rotate(bogus);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      TestUtil.assertExceptionContains(e, "No key manager found for key type");
    }
  }

  @Test
  public void testRotate_existingKeyset_shouldAddNewKeyAndSetPrimaryKeyId() throws Exception {
    KeysetHandle existing = KeysetManager.withEmptyKeyset()
        .rotate(MacKeyTemplates.HMAC_SHA256_128BITTAG)
        .getKeysetHandle();
    Keyset keyset = KeysetManager.withKeysetHandle(existing)
        .rotate(MacKeyTemplates.HMAC_SHA256_256BITTAG)
        .getKeysetHandle()
        .getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(keyset.getKey(1).getKeyId());
    TestUtil.assertHmacKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, keyset.getKey(0));
    TestUtil.assertHmacKey(MacKeyTemplates.HMAC_SHA256_256BITTAG, keyset.getKey(1));
  }

  @Test
  public void testAdd_shouldAddNewKey() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    Keyset keyset = KeysetManager
        .withEmptyKeyset()
        .add(template)
        .getKeysetHandle()
        .getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(0);
    TestUtil.assertHmacKey(template, keyset.getKey(0));
  }

  @Test
  public void testAdd_bogusKeyTemplate_shouldThrowException() throws Exception {
    KeyTemplate bogus = TestUtil.createKeyTemplateWithNonExistingTypeUrl();

    try {
      KeysetManager
          .withEmptyKeyset()
          .add(bogus);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      TestUtil.assertExceptionContains(e, "No key manager found for key type");
    }
  }

  @Test
  public void testAdd_existingKeySet_shouldAddNewKey() throws Exception {
    KeysetHandle existing = KeysetManager.withEmptyKeyset()
        .rotate(MacKeyTemplates.HMAC_SHA256_128BITTAG)
        .getKeysetHandle();
    int existingPrimaryKeyId = existing.getKeyset().getPrimaryKeyId();
    Keyset keyset = KeysetManager.withKeysetHandle(existing)
        .add(MacKeyTemplates.HMAC_SHA256_256BITTAG)
        .getKeysetHandle()
        .getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(existingPrimaryKeyId);
    TestUtil.assertHmacKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, keyset.getKey(0));
    TestUtil.assertHmacKey(MacKeyTemplates.HMAC_SHA256_256BITTAG, keyset.getKey(1));
  }
}
