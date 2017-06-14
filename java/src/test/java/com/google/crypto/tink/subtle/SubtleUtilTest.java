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

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for SubtleUtil.
 */
@RunWith(JUnit4.class)
public class SubtleUtilTest {
  @Test
  public void testValidateCloudKmsCryptoKeyUri() throws Exception {
    try {
      SubtleUtil.validateCloudKmsCryptoKeyUri("a");
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertExceptionContains(e, "Invalid Google Cloud KMS Key URI");
    }

    String cryptoKey = TestUtil.createGcpKmsKeyUri(
        "projectId", "locationId", "ringId", "cryptoKeyId");
    try {
      SubtleUtil.validateCloudKmsCryptoKeyUri(cryptoKey);
    } catch (IllegalArgumentException e) {
      fail("Valid CryptoKey URI should work: " + cryptoKey);
    }

    String cryptoVersion = cryptoKey + "/cryptoKeyVersions/versionId";
    try {
      SubtleUtil.validateCloudKmsCryptoKeyUri(cryptoVersion);
      fail("CryptoKeyVersion is not a valid CryptoKey");
    } catch (IllegalArgumentException e) {
      assertExceptionContains(e, "The URI must point to a CryptoKey, not a CryptoKeyVersion");
    }
  }
}
