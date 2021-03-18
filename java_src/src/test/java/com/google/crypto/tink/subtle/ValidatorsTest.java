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

package com.google.crypto.tink.subtle;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.testing.TestUtil;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Validators}. */
@RunWith(JUnit4.class)
public class ValidatorsTest {
  @Rule public TemporaryFolder tmpFolder = new TemporaryFolder();

  @Test
  public void testValidateTypeUrl() throws Exception {
    String goodUrlPrefix = "type.googleapis.com/";

    // Some invalid type URLs.
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> Validators.validateTypeUrl("some.bad.url/that.is.invalid"));
    TestUtil.assertExceptionContains(e, "type URL");
    TestUtil.assertExceptionContains(e, "invalid");
    GeneralSecurityException e2 =
        assertThrows(
            GeneralSecurityException.class, () -> Validators.validateTypeUrl(goodUrlPrefix));
    TestUtil.assertExceptionContains(e2, "type URL");
    TestUtil.assertExceptionContains(e2, "invalid");
    TestUtil.assertExceptionContains(e2, "has no message name");
    // A valid type URL.
    Validators.validateTypeUrl(goodUrlPrefix + "somepackage.somemessage");
  }

  @Test
  public void testValidateAesKeySize() throws Exception {
    Validators.validateAesKeySize(16);
    Validators.validateAesKeySize(32);

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> Validators.validateAesKeySize(24));
    TestUtil.assertExceptionContains(e, "invalid");
    TestUtil.assertExceptionContains(e, "key size");
    int count = 0;
    for (int j = -100; j <= 100; j++) {
      final int i = j;
      if ((i != 16) && (i != 32)) {
        GeneralSecurityException e2 =
            assertThrows(GeneralSecurityException.class, () -> Validators.validateAesKeySize(i));
        count++;
        TestUtil.assertExceptionContains(e2, "invalid");
        TestUtil.assertExceptionContains(e2, "key size");
      }
    }
    assertEquals(201 - 2, count);
  }

  @Test
  public void testValidateVersion() throws Exception {
    int maxVersion = 1;
    int count = 0;
    int countNegative = 0;
    for (int i = -maxVersion; i <= maxVersion; i++) {
      final int maxExpected = i;
      for (int j = -maxVersion; j <= maxVersion; j++) {
        final int candidate = j;
        if (candidate < 0 || maxExpected < 0) {
          GeneralSecurityException e =
              assertThrows(
                  GeneralSecurityException.class,
                  () -> Validators.validateVersion(candidate, maxExpected));
          countNegative++;
          TestUtil.assertExceptionContains(e, "version");
        } else {
          if (candidate <= maxExpected) {
            Validators.validateVersion(candidate, maxExpected);
          } else {
            GeneralSecurityException e2 =
                assertThrows(
                    GeneralSecurityException.class,
                    () -> Validators.validateVersion(candidate, maxExpected));
            count++;
            TestUtil.assertExceptionContains(e2, "version");
          }
        }
      }
    }
    assertEquals(maxVersion * (maxVersion + 1) / 2, count);
    // countNegative == (2*maxVersion + 1)^2 - (maxVersion+1^2)
    assertEquals(maxVersion * (3 * maxVersion + 2), countNegative);
  }

  @Test
  public void testValidateSignatureHash() throws Exception {
    try {
      Validators.validateSignatureHash(HashType.SHA256);
      Validators.validateSignatureHash(HashType.SHA512);
    } catch (GeneralSecurityException e) {
      fail("Valid signature algorithm should work " + e);
    }
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> Validators.validateSignatureHash(HashType.SHA1));
    TestUtil.assertExceptionContains(e, "Unsupported hash: SHA1");
  }

  @Test
  public void testValidateRsaPublicExponent() throws Exception {
    Validators.validateRsaPublicExponent(BigInteger.valueOf(65537));
    assertThrows(
        GeneralSecurityException.class,
        () -> Validators.validateRsaPublicExponent(BigInteger.valueOf(65535)));
    assertThrows(
        GeneralSecurityException.class,
        () -> Validators.validateRsaPublicExponent(BigInteger.valueOf(65538)));
  }

  @Test
  public void testValidateFileExistence() throws Exception {
    // In Before, Test, or After:
    File tmpDir = tmpFolder.getRoot();
    String tmpDirPath = tmpDir.getAbsolutePath();

    File file = new File(tmpDirPath + "some_file.tmp");

    // The file doesn't exist yet.
    Validators.validateNotExists(file);
    assertThrows(IOException.class, () -> Validators.validateExists(file));

    file.createNewFile();

    // Now the file exists.
    Validators.validateExists(file);
    assertThrows(IOException.class, () -> Validators.validateNotExists(file));
  }

  @Test
  public void testValidateCryptoKeyUri() throws Exception {
    GeneralSecurityException exception =
        assertThrows(GeneralSecurityException.class, () -> Validators.validateCryptoKeyUri("a"));
    TestUtil.assertExceptionContains(exception, "Invalid Google Cloud KMS Key URI");

    String cryptoKey =
        TestUtil.createGcpKmsKeyUri("projectId", "locationId", "ringId", "cryptoKeyId");
    try {
      Validators.validateCryptoKeyUri(cryptoKey);
    } catch (GeneralSecurityException e) {
      fail("Valid CryptoKey URI should work: " + cryptoKey);
    }

    cryptoKey = TestUtil.createGcpKmsKeyUri("projectId.", "locationId-", "ringId_", "cryptoKeyId~");
    try {
      Validators.validateCryptoKeyUri(cryptoKey);
    } catch (GeneralSecurityException e) {
      fail("Valid CryptoKey URI should work: " + cryptoKey);
    }

    final String cryptoKey2 =
        TestUtil.createGcpKmsKeyUri("projectId%", "locationId", "ringId", "cryptoKeyId");
    assertThrows(GeneralSecurityException.class, () -> Validators.validateCryptoKeyUri(cryptoKey2));

    final String cryptoKey3 =
        TestUtil.createGcpKmsKeyUri("projectId/", "locationId", "ringId", "cryptoKeyId");
    assertThrows(GeneralSecurityException.class, () -> Validators.validateCryptoKeyUri(cryptoKey3));

    String cryptoVersion =
        TestUtil.createGcpKmsKeyUri("projectId", "locationId", "ringId", "cryptoKeyId")
            + "/cryptoKeyVersions/versionId";
    GeneralSecurityException e2 =
        assertThrows(
            GeneralSecurityException.class, () -> Validators.validateCryptoKeyUri(cryptoVersion));
    TestUtil.assertExceptionContains(
        e2, "The URI must point to a CryptoKey, not a CryptoKeyVersion");
  }
}
