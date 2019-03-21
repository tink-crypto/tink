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

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

// TODO(b/74251398): add tests for other functions.
/** Tests for Util. */
@RunWith(JUnit4.class)
public class UtilTest {
  @Test
  public void testValidateKeyset_shouldWork() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
                -42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    try {
      Util.validateKeyset(keyset);
    } catch (GeneralSecurityException e) {
      fail("Valid keyset; should not throw Exception: " + e);
    }
  }

  @Test
  public void testValidateKeyset_emptyKeyset_shouldFail() throws Exception {
    try {
      Util.validateKeyset(Keyset.newBuilder().build());
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset must contain at least one ENABLED key");
    }
  }

  @Test
  public void testValidateKeyset_multiplePrimaryKeys_shouldFail() throws Exception {
    String keyValue = "01234567890123456";
    // Multiple primary keys.
    Keyset invalidKeyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK),
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    try {
      Util.validateKeyset(invalidKeyset);
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset contains multiple primary keys");
    }
  }

  @Test
  public void testValidateKeyset_primaryKeyIsDisabled_shouldFail() throws Exception {
    String keyValue = "01234567890123456";
    // Primary key is disabled.
    Keyset invalidKeyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
                42,
                KeyStatusType.DISABLED,
                OutputPrefixType.TINK),
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
                43,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    try {
      Util.validateKeyset(invalidKeyset);
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset doesn't contain a valid primary key");
    }
  }

  @Test
  public void testValidateKeyset_noEnabledKey_shouldFail() throws Exception {
    String keyValue = "01234567890123456";
    // No ENABLED key.
    Keyset invalidKeyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
                42,
                KeyStatusType.DISABLED,
                OutputPrefixType.TINK),
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
                42,
                KeyStatusType.DESTROYED,
                OutputPrefixType.TINK));
    try {
      Util.validateKeyset(invalidKeyset);
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset must contain at least one ENABLED key");
    }
  }

  @Test
  public void testValidateKeyset_noPrimaryKey_shouldFail() throws Exception {
    String keyValue = "01234567890123456";
    // No primary key.
    Keyset invalidKeyset =
        Keyset.newBuilder()
            .addKey(
                Keyset.Key.newBuilder()
                    .setKeyData(TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16))
                    .setKeyId(1)
                    .setStatus(KeyStatusType.ENABLED)
                    .setOutputPrefixType(OutputPrefixType.TINK)
                    .build())
            .build();
    try {
      Util.validateKeyset(invalidKeyset);
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset doesn't contain a valid primary key");
    }
  }

  @Test
  public void testValidateKeyset_noPrimaryKey_keysetContainsOnlyPublicKeys_shouldWork()
      throws Exception {
    // No primary key, but contains only public key material.
    Keyset validKeyset =
        Keyset.newBuilder()
            .addKey(
                Keyset.Key.newBuilder()
                    .setKeyData(
                        TestUtil.createKeyData(
                            KeyData.newBuilder().build(),
                            "typeUrl",
                            KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC))
                    .setKeyId(1)
                    .setStatus(KeyStatusType.ENABLED)
                    .setOutputPrefixType(OutputPrefixType.TINK)
                    .build())
            .build();
    try {
      Util.validateKeyset(validKeyset);
    } catch (GeneralSecurityException e) {
      fail("Valid keyset, should not fail: " + e);
    }
  }

  @Test
  public void testValidateKeyset_withDestroyedKey_shouldWork() throws Exception {
    String keyValue = "01234567890123456";
    Keyset validKeyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK),
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
                42,
                KeyStatusType.DESTROYED,
                OutputPrefixType.TINK));
    try {
      Util.validateKeyset(validKeyset);
    } catch (GeneralSecurityException e) {
      fail("Valid keyset, should not fail: " + e);
    }
  }

  /** Tests that getKeysetInfo doesn't contain key material. */
  @Test
  public void testGetKeysetInfo() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    assertTrue(keyset.toString().contains(keyValue));

    KeysetInfo keysetInfo = Util.getKeysetInfo(keyset);
    assertFalse(keysetInfo.toString().contains(keyValue));
  }

  @Test
  public void testAssertExceptionContains() throws Exception {
    assertExceptionContains(new GeneralSecurityException("abc"), "abc");

    try {
      assertExceptionContains(new GeneralSecurityException("abc"), "def");
    } catch (AssertionError e) {
      assertExceptionContains(
          e, "Got exception with message \"abc\", expected it to contain \"def\".");
    }
  }
}
