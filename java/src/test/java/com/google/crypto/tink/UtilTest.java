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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.hybrid.HybridKeyTemplates;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import java.security.GeneralSecurityException;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for Util. */
@RunWith(JUnit4.class)
public class UtilTest {
  @Test
  public void testValidateKeyset() throws Exception {
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

    // Empty keyset.
    try {
      Util.validateKeyset(Keyset.newBuilder().build());
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }

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

    // Primary key is disabled.
    invalidKeyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
                42,
                KeyStatusType.DISABLED,
                OutputPrefixType.TINK));
    try {
      Util.validateKeyset(invalidKeyset);
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset doesn't contain a valid primary key");
    }

    // No primary key.
    invalidKeyset =
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

  @Test
  public void testGetHashType() throws Exception {
    // Test basic.
    assertEquals(HashType.SHA1, Util.getHashType("SHA1"));
    assertEquals(HashType.SHA224, Util.getHashType("SHA224"));
    assertEquals(HashType.SHA256, Util.getHashType("SHA256"));
    assertEquals(HashType.SHA512, Util.getHashType("SHA512"));

    // Test case-insensitivity.
    assertEquals(HashType.SHA1, Util.getHashType("sha1"));
    assertEquals(HashType.SHA1, Util.getHashType("Sha1"));
    assertEquals(HashType.SHA224, Util.getHashType("sha224"));
    assertEquals(HashType.SHA224, Util.getHashType("Sha224"));
    assertEquals(HashType.SHA256, Util.getHashType("sha256"));
    assertEquals(HashType.SHA256, Util.getHashType("Sha256"));
    assertEquals(HashType.SHA512, Util.getHashType("sha512"));
    assertEquals(HashType.SHA512, Util.getHashType("Sha512"));

    // Test unknown.
    try {
      Util.getHashType("SHA42");
      fail("Unknown hash, should have thrown exception");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "unknown hash type");
    }
    try {
      Util.getHashType("another one");
      fail("Unknown hash, should have thrown exception");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "unknown hash type");
    }
  }

  @Test
  public void testGetOutputPrefixType() throws Exception {
    // Test basic.
    assertEquals(OutputPrefixType.TINK, Util.getOutputPrefixType("TINK"));
    assertEquals(OutputPrefixType.LEGACY, Util.getOutputPrefixType("LEGACY"));
    assertEquals(OutputPrefixType.RAW, Util.getOutputPrefixType("RAW"));
    assertEquals(OutputPrefixType.CRUNCHY, Util.getOutputPrefixType("CRUNCHY"));

    // Test case-insensitivity.
    assertEquals(OutputPrefixType.TINK, Util.getOutputPrefixType("tink"));
    assertEquals(OutputPrefixType.TINK, Util.getOutputPrefixType("Tink"));
    assertEquals(OutputPrefixType.LEGACY, Util.getOutputPrefixType("legacy"));
    assertEquals(OutputPrefixType.LEGACY, Util.getOutputPrefixType("Legacy"));
    assertEquals(OutputPrefixType.RAW, Util.getOutputPrefixType("raw"));
    assertEquals(OutputPrefixType.RAW, Util.getOutputPrefixType("Raw"));
    assertEquals(OutputPrefixType.CRUNCHY, Util.getOutputPrefixType("crunchy"));
    assertEquals(OutputPrefixType.CRUNCHY, Util.getOutputPrefixType("Crunchy"));

    // Test unknown.
    try {
      Util.getOutputPrefixType("CUSTOM");
      fail("Unknown output prefix, should have thrown exception");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "unknown output prefix type");
    }
    try {
      Util.getOutputPrefixType("TINKY");  // Misspelled.
      fail("Unknown output prefix, should have thrown exception");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "unknown output prefix type");
    }
    try {
      Util.getOutputPrefixType("row");  // Misspelled too.
      fail("Unknown output prefix, should have thrown exception");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "unknown output prefix type");
    }
  }

  @Test
  public void testGetEllipticCurveType() throws Exception {
    // Test basic.
    assertEquals(EllipticCurveType.NIST_P224, Util.getEllipticCurveType("NIST_P224"));
    assertEquals(EllipticCurveType.NIST_P256, Util.getEllipticCurveType("NIST_P256"));
    assertEquals(EllipticCurveType.NIST_P384, Util.getEllipticCurveType("NIST_P384"));
    assertEquals(EllipticCurveType.NIST_P521, Util.getEllipticCurveType("NIST_P521"));

    // Test case-insensitivity.
    assertEquals(EllipticCurveType.NIST_P224, Util.getEllipticCurveType("nist_p224"));
    assertEquals(EllipticCurveType.NIST_P224, Util.getEllipticCurveType("Nist_p224"));
    assertEquals(EllipticCurveType.NIST_P256, Util.getEllipticCurveType("nist_p256"));
    assertEquals(EllipticCurveType.NIST_P256, Util.getEllipticCurveType("Nist_p256"));
    assertEquals(EllipticCurveType.NIST_P384, Util.getEllipticCurveType("nist_p384"));
    assertEquals(EllipticCurveType.NIST_P384, Util.getEllipticCurveType("Nist_p384"));
    assertEquals(EllipticCurveType.NIST_P521, Util.getEllipticCurveType("nist_p521"));
    assertEquals(EllipticCurveType.NIST_P521, Util.getEllipticCurveType("Nist_p521"));

    // Test unknown.
    try {
      Util.getEllipticCurveType("NIST_P42");
      fail("Unknown elliptic curve, should have thrown exception");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "unknown elliptic curve type");
    }
    try {
      Util.getEllipticCurveType("NIST_P128");
      fail("Unknown elliptic curve, should have thrown exception");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "unknown elliptic curve type");
    }
    try {
      Util.getEllipticCurveType("my EC");
      fail("Unknown elliptic curve, should have thrown exception");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "unknown elliptic curve type");
    }
  }

  @Test
  public void testGetEcPointFormat() throws Exception {
    // Test basic.
    assertEquals(EcPointFormat.COMPRESSED, Util.getEcPointFormat("COMPRESSED"));
    assertEquals(EcPointFormat.UNCOMPRESSED, Util.getEcPointFormat("UNCOMPRESSED"));

    // Test case-insensitivity.
    assertEquals(EcPointFormat.COMPRESSED, Util.getEcPointFormat("compressed"));
    assertEquals(EcPointFormat.COMPRESSED, Util.getEcPointFormat("Compressed"));
    assertEquals(EcPointFormat.UNCOMPRESSED, Util.getEcPointFormat("uncompressed"));
    assertEquals(EcPointFormat.UNCOMPRESSED, Util.getEcPointFormat("Uncompressed"));

    // Test unknown.
    try {
      Util.getEcPointFormat("compressed42");
      fail("Unknown EC point format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "unknown EC point format");
    }
    try {
      Util.getEcPointFormat("compresed");  // Misspelled.
      fail("Unknown EC point format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "unknown EC point format");
    }
  }

  @Test
  public void testJsonExportOfKeyTemplates() throws Exception {
    Config.register(HybridConfig.TINK_1_0_0);  // Contains Aead.

    int templateCount = 4;
    KeyTemplate[] templates = new KeyTemplate[templateCount];
    templates[0] = AeadKeyTemplates.AES128_CTR_HMAC_SHA256;
    templates[1] = AeadKeyTemplates.AES256_GCM;
    templates[2] = HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM;
    templates[3] = HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256;

    int count = 0;
    for (KeyTemplate template : templates) {
      try {
        JSONObject json = Util.toJson(template);
        KeyTemplate templateFromJson = Util.keyTemplateFromJson(json);
        assertEquals(template.toString(), templateFromJson.toString());
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for template: " + template.toString());
      }
      count++;
    }
    assertEquals(templateCount, count);
  }

  // TODO(thaidn): add tests for other functions.
}
