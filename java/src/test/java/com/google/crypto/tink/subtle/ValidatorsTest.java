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
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.subtle.Enums.HashType;
import java.io.File;
import java.io.IOException;
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
    try {
      Validators.validateTypeUrl("some.bad.url/that.is.invalid");
      fail("Invalid type URL, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      TestUtil.assertExceptionContains(e, "type URL");
      TestUtil.assertExceptionContains(e, "invalid");
    }
    try {
      Validators.validateTypeUrl(goodUrlPrefix);
      fail("Invalid type URL, should have thrown exception.");
    } catch (GeneralSecurityException e) {
      // Expected.
      TestUtil.assertExceptionContains(e, "type URL");
      TestUtil.assertExceptionContains(e, "invalid");
      TestUtil.assertExceptionContains(e, "has no message name");
    }

    // A valid type URL.
    Validators.validateTypeUrl(goodUrlPrefix + "somepackage.somemessage");
  }

  @Test
  public void testValidateAesKeySize() throws Exception {
    Validators.validateAesKeySize(16);
    Validators.validateAesKeySize(32);

    try {
      Validators.validateAesKeySize(24);
      fail("Invalid AES key size, should have thrown exception.");
    } catch (GeneralSecurityException e) {
      // Expected.
      TestUtil.assertExceptionContains(e, "invalid");
      TestUtil.assertExceptionContains(e, "key size");
    }

    int count = 0;
    for (int i = -100; i <= 100; i++) {
      if ((i != 16) && (i != 32)) {
        try {
          Validators.validateAesKeySize(i);
          fail("Invalid AES key size, should have thrown exception.");
        } catch (GeneralSecurityException e) {
          // Expected.
          count++;
          TestUtil.assertExceptionContains(e, "invalid");
          TestUtil.assertExceptionContains(e, "key size");
        }
      }
    }
    assertEquals(201 - 2, count);
  }

  @Test
  public void testValidateVersion() throws Exception {
    int maxVersion = 1;
    int count = 0;
    int countNegative = 0;
    for (int maxExpected = -maxVersion; maxExpected <= maxVersion; maxExpected++) {
      for (int candidate = -maxVersion; candidate <= maxVersion; candidate++) {
        if (candidate < 0 || maxExpected < 0) {
          try {
            Validators.validateVersion(candidate, maxExpected);
            fail("Negative version parameters, should have thrown exception.");
          } catch (GeneralSecurityException e) {
            // Expected.
            countNegative++;
            TestUtil.assertExceptionContains(e, "version");
          }
        } else {
          if (candidate <= maxExpected) {
            Validators.validateVersion(candidate, maxExpected);
          } else {
            try {
              Validators.validateVersion(candidate, maxExpected);
              fail("Invalid key version, should have thrown exception.");
            } catch (GeneralSecurityException e) {
              // Expected.
              count++;
              TestUtil.assertExceptionContains(e, "version");
            }
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
    try {
      Validators.validateSignatureHash(HashType.SHA1);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      TestUtil.assertExceptionContains(e, "SHA1 is not safe");
    }
  }

  @Test
  public void testValidateFileExistence() throws Exception {
    // In Before, Test, or After:
    File tmpDir = tmpFolder.getRoot();
    String tmpDirPath = tmpDir.getAbsolutePath();

    File file = new File(tmpDirPath + "some_file.tmp");

    // The file doesn't exist yet.
    Validators.validateNotExists(file);
    try {
      Validators.validateExists(file);
      fail("File doesn't exist, should have thrown exception.");
    } catch (IOException e) {
      // Expected.
    }

    file.createNewFile();

    // Now the file exists.
    Validators.validateExists(file);
    try {
      Validators.validateNotExists(file);
      fail("File exists, should have thrown exception.");
    } catch (IOException e) {
      // Expected.
    }
  }

  @Test
  public void testValidateCryptoKeyUri() throws Exception {
    try {
      Validators.validateCryptoKeyUri("a");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      TestUtil.assertExceptionContains(e, "Invalid Google Cloud KMS Key URI");
    }

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

    cryptoKey = TestUtil.createGcpKmsKeyUri("projectId%", "locationId", "ringId", "cryptoKeyId");
    try {
      Validators.validateCryptoKeyUri(cryptoKey);
      fail("CryptoKey URI cannot contain %");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    cryptoKey = TestUtil.createGcpKmsKeyUri("projectId/", "locationId", "ringId", "cryptoKeyId");
    try {
      Validators.validateCryptoKeyUri(cryptoKey);
      fail("CryptoKey URI cannot contain /");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    String cryptoVersion =
        TestUtil.createGcpKmsKeyUri("projectId", "locationId", "ringId", "cryptoKeyId")
            + "/cryptoKeyVersions/versionId";
    try {
      Validators.validateCryptoKeyUri(cryptoVersion);
      fail("CryptoKeyVersion is not a valid CryptoKey");
    } catch (GeneralSecurityException e) {
      TestUtil.assertExceptionContains(
          e, "The URI must point to a CryptoKey, not a CryptoKeyVersion");
    }
  }
}
