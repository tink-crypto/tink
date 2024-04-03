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
import static com.google.crypto.tink.testing.TestUtil.assertExceptionContains;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.crypto.tink.internal.SlowInputStream;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for Util. */
@RunWith(JUnit4.class)
public class UtilTest {

  @Test
  public void testValidateKey_success() throws Exception {
    String keyValue = "0123456789012345";
    Keyset.Key key =
        TestUtil.createKey(
            TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    Util.validateKey(key);
  }

  @Test
  public void testValidateKey_emptyKeyData_success() throws Exception {
    Keyset.Key key =
        TestUtil.createKey(
            KeyData.getDefaultInstance(), 42, KeyStatusType.ENABLED, OutputPrefixType.TINK);
    Util.validateKey(key);
  }

  @Test
  public void testValidateKey_noKeyData_fails() throws Exception {
    Keyset.Key key =
        Keyset.Key.newBuilder()
            .setStatus(KeyStatusType.ENABLED)
            .setKeyId(42)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    assertThrows(GeneralSecurityException.class, () -> Util.validateKey(key));
  }

  @Test
  public void testValidateKey_unknownPrefix_fails() throws Exception {
    String keyValue = "0123456789012345";
    Keyset.Key key =
        TestUtil.createKey(
            TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.UNKNOWN_PREFIX);
    assertThrows(GeneralSecurityException.class, () -> Util.validateKey(key));
  }

  @Test
  public void testValidateKey_unknownStatus_fails() throws Exception {
    String keyValue = "0123456789012345";
    Keyset.Key key =
        TestUtil.createKey(
            TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
            42,
            KeyStatusType.UNKNOWN_STATUS,
            OutputPrefixType.TINK);
    assertThrows(GeneralSecurityException.class, () -> Util.validateKey(key));
  }

  @Test
  public void testValidateKeyset_shouldWork() throws Exception {
    String keyValue = "0123456789012345";
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
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
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> Util.validateKeyset(Keyset.getDefaultInstance()));
    assertExceptionContains(e, "keyset must contain at least one ENABLED key");
  }

  @Test
  public void testValidateKeyset_multiplePrimaryKeys_shouldFail() throws Exception {
    String keyValue = "0123456789012345";
    // Multiple primary keys.
    Keyset invalidKeyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK),
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> Util.validateKeyset(invalidKeyset));
    assertExceptionContains(e, "keyset contains multiple primary keys");
  }

  @Test
  public void testValidateKeyset_primaryKeyIsDisabled_shouldFail() throws Exception {
    String keyValue = "0123456789012345";
    // Primary key is disabled.
    Keyset invalidKeyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.DISABLED,
                OutputPrefixType.TINK),
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                43,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> Util.validateKeyset(invalidKeyset));
    assertExceptionContains(e, "keyset doesn't contain a valid primary key");
  }

  @Test
  public void testValidateKeyset_noEnabledKey_shouldFail() throws Exception {
    String keyValue = "0123456789012345";
    // No ENABLED key.
    Keyset invalidKeyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.DISABLED,
                OutputPrefixType.TINK),
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.DESTROYED,
                OutputPrefixType.TINK));
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> Util.validateKeyset(invalidKeyset));
    assertExceptionContains(e, "keyset must contain at least one ENABLED key");
  }

  @Test
  public void testValidateKeyset_noPrimaryKey_shouldFail() throws Exception {
    String keyValue = "0123456789012345";
    // No primary key.
    Keyset invalidKeyset =
        Keyset.newBuilder()
            .addKey(
                Keyset.Key.newBuilder()
                    .setKeyData(TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16))
                    .setKeyId(1)
                    .setStatus(KeyStatusType.ENABLED)
                    .setOutputPrefixType(OutputPrefixType.TINK)
                    .build())
            .build();
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> Util.validateKeyset(invalidKeyset));
    assertExceptionContains(e, "keyset doesn't contain a valid primary key");
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
                            KeyData.getDefaultInstance(),
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
    String keyValue = "0123456789012345";
    Keyset validKeyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK),
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.DESTROYED,
                OutputPrefixType.TINK));
    try {
      Util.validateKeyset(validKeyset);
    } catch (GeneralSecurityException e) {
      fail("Valid keyset, should not fail: " + e);
    }
  }

  @Test
  public void testValidateKeyset_withUnknownStatusKey_works() throws Exception {
    String keyValue = "0123456789012345";
    Keyset keyset =
        TestUtil.createKeyset(
            /* primary= */ TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK),
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                123,
                KeyStatusType.UNKNOWN_STATUS,
                OutputPrefixType.TINK));
    Util.validateKeyset(keyset);
  }

  @Test
  public void testGetKeyInfo_works() throws Exception {
    String keyValue = "0123456789012345";
    Keyset.Key key =
        TestUtil.createKey(
            TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    KeysetInfo.KeyInfo keyInfo = Util.getKeyInfo(key);
    assertThat(keyInfo)
        .isEqualTo(
            KeysetInfo.KeyInfo.newBuilder()
                .setTypeUrl("type.googleapis.com/google.crypto.tink.HmacKey")
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.TINK)
                .setKeyId(42)
                .build());
  }

  @Test
  public void testGetKeysetInfo_works() throws Exception {
    Keyset keyset =
        TestUtil.createKeyset(
            /* primary= */ TestUtil.createKey(
                TestUtil.createHmacKeyData("0123456789012345".getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK),
            TestUtil.createKey(
                TestUtil.createHmacKeyData("1234567890123456".getBytes(UTF_8), 16),
                123,
                KeyStatusType.DISABLED,
                OutputPrefixType.RAW));
    KeysetInfo keysetInfo = Util.getKeysetInfo(keyset);
    assertThat(keysetInfo)
        .isEqualTo(
            KeysetInfo.newBuilder()
                .setPrimaryKeyId(42)
                .addKeyInfo(
                    KeysetInfo.KeyInfo.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.HmacKey")
                        .setStatus(KeyStatusType.ENABLED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .setKeyId(42)
                        .build())
                .addKeyInfo(
                    KeysetInfo.KeyInfo.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.HmacKey")
                        .setStatus(KeyStatusType.DISABLED)
                        .setOutputPrefixType(OutputPrefixType.RAW)
                        .setKeyId(123)
                        .build())
                .build());
  }

  @Test
  public void testGetKeysetInfo_doesNotContainKeyMaterial() throws Exception {
    String keyValue = "0123456789012345";
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    assertThat(keyset.toString()).contains(keyValue);

    KeysetInfo keysetInfo = Util.getKeysetInfo(keyset);
    assertThat(keysetInfo.toString()).doesNotContain(keyValue);
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

  @Test
  public void testReadAll() throws Exception {
    byte[] input = Random.randBytes(2000);
    InputStream stream = new ByteArrayInputStream(input);
    byte[] output = Util.readAll(stream);
    assertThat(output).isEqualTo(input);
  }

  @Test
  public void testReadAllWithSlowInputStream() throws Exception {
    byte[] input = Random.randBytes(2000);
    InputStream stream = SlowInputStream.copyFrom(input);
    byte[] output = Util.readAll(stream);
    assertThat(output).isEqualTo(input);
  }
}
