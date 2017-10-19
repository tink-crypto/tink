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
// See the License for the specified language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink;

import static org.junit.Assert.fail;

import org.json.JSONObject;

/** Wycheproof Test helpers. */
public class WycheproofTestUtil {
  /**
   * Returns the algorithm name for a digital signature algorithm with a given message digest. The
   * algorithm names used in JCA are a bit inconsequential. E.g. a dash is necessary for message
   * digests (e.g. "SHA-256") but are not used in the corresponding names for digital signatures
   * (e.g. "SHA256WITHECDSA").
   *
   * <p>See http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
   *
   * @param md the name of the message digest (e.g. "SHA-256")
   * @param signatureAlgorithm the name of the signature algorithm (e.g. "ECDSA")
   * @return the algorithm name for the signature scheme with the given hash.
   */
  public static String getSignatureAlgorithmName(String md, String signatureAlgorithm) {
    if (md.equals("SHA-256")) {
      md = "SHA256";
    } else if (md.equals("SHA-512")) {
      md = "SHA512";
    } else {
      return "";
    }
    return md + "WITH" + signatureAlgorithm;
  }

  /**
   * Checks that test vector has the expected algorithm and version.
   */
  public static void checkAlgAndVersion(
      JSONObject testvector, String expectedAlgorithm, String expectedVersion) throws Exception {
    String algorithm = testvector.getString("algorithm");
    if (!expectedAlgorithm.equals(algorithm)) {
      fail("expect algorithm " + expectedAlgorithm + ", got" + algorithm);
    }
    String generatorVersion = testvector.getString("generatorVersion");
    if (!generatorVersion.equals(expectedVersion)) {
      fail(
          "expect test vectors with version "
              + expectedVersion
              + " ,got vectors with version "
              + generatorVersion);
    }
  }
}
