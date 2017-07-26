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

package com.google.crypto.tink.integration;

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for IntegrationUtil.
 */
@RunWith(JUnit4.class)
public class IntegrationUtilTest {
  @Test
  public void testValidateCryptoKeyUri() throws Exception {
    try {
      IntegrationUtil.validateCryptoKeyUri("a");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "Invalid Google Cloud KMS Key URI");
    }

    String cryptoKey = TestUtil.createGcpKmsKeyUri(
        "projectId", "locationId", "ringId", "cryptoKeyId");
    try {
      IntegrationUtil.validateCryptoKeyUri(cryptoKey);
    } catch (GeneralSecurityException e) {
      fail("Valid CryptoKey URI should work: " + cryptoKey);
    }

    cryptoKey = TestUtil.createGcpKmsKeyUri(
        "projectId.", "locationId-", "ringId_", "cryptoKeyId~");
    try {
      IntegrationUtil.validateCryptoKeyUri(cryptoKey);
    } catch (GeneralSecurityException e) {
      fail("Valid CryptoKey URI should work: " + cryptoKey);
    }

    cryptoKey = TestUtil.createGcpKmsKeyUri(
        "projectId%", "locationId", "ringId", "cryptoKeyId");
    try {
      IntegrationUtil.validateCryptoKeyUri(cryptoKey);
      fail("CryptoKey URI cannot contain %");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    cryptoKey = TestUtil.createGcpKmsKeyUri(
        "projectId/", "locationId", "ringId", "cryptoKeyId");
    try {
      IntegrationUtil.validateCryptoKeyUri(cryptoKey);
      fail("CryptoKey URI cannot contain /");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    String cryptoVersion = TestUtil.createGcpKmsKeyUri(
        "projectId", "locationId", "ringId", "cryptoKeyId") + "/cryptoKeyVersions/versionId";
    try {
      IntegrationUtil.validateCryptoKeyUri(cryptoVersion);
      fail("CryptoKeyVersion is not a valid CryptoKey");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "The URI must point to a CryptoKey, not a CryptoKeyVersion");
    }
  }
}
