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

package com.google.crypto.tink.testing;

import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;

/** Wycheproof Test helpers. */
public final class WycheproofTestUtil {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  /**
   * Gets hash type from hash name.
   *
   * @param md the name of the message digest (e.g. "SHA-256").
   * @return the hash type.
   * @throws NoSuchAlgorithmException iff the hash name is unknown.
   */
  public static HashType getHashType(String md) throws NoSuchAlgorithmException {
    switch (md) {
      case "SHA-256":
        return HashType.SHA256;
      case "SHA-512":
        return HashType.SHA512;
      case "SHA-1":
        return HashType.SHA1;
      default:
        throw new NoSuchAlgorithmException("Unsupported hash name: " + md);
    }
  }

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
   * Reads all bytes from {@code inputStream}.
   */
  private static byte[] readAll(InputStream inputStream) throws IOException {
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    byte[] buf = new byte[1024];
    int count;
    while ((count = inputStream.read(buf)) != -1) {
      result.write(buf, 0, count);
    }
    return result.toByteArray();
  }

  /** Gets JsonObject from file. */
  public static JsonObject readJson(String path) throws Exception {
    String filePath = path;
    if (TestUtil.isAndroid()) {
      // TODO(b/67385998): make this work outside google3.
      filePath = "/sdcard/googletest/test_runfiles/google3/" + path;
    }
    JsonObject result;
    try (FileInputStream fileInputStream = new FileInputStream(new File(filePath))) {
      result =
          JsonParser.parseString(new String(readAll(fileInputStream), UTF_8)).getAsJsonObject();
    }
    String algorithm = result.get("algorithm").getAsString();
    String generatorVersion = result.get("generatorVersion").getAsString();
    int numTests = result.get("numberOfTests").getAsInt();
    System.out.println(
        String.format(
            "Read from %s total %d test cases for algorithm %s with generator version %s",
            path, numTests, algorithm, generatorVersion));
    return result;
  }
  /**
   * Gets curve type from curve name.
   *
   * @throws NoSuchAlgorithmException iff the curve name is unknown.
   */
  public static EllipticCurves.CurveType getCurveType(String curveName)
      throws NoSuchAlgorithmException {
    switch (curveName) {
      case "secp256r1":
        return EllipticCurves.CurveType.NIST_P256;
      case "secp384r1":
        return EllipticCurves.CurveType.NIST_P384;
      case "secp521r1":
        return EllipticCurves.CurveType.NIST_P521;
      default:
        throw new NoSuchAlgorithmException("Unknown curve name: " + curveName);
    }
  }

  /** @return true if the test case has one of the flags. */
  public static boolean checkFlags(JsonObject testcase, String... flags) throws Exception {
    JsonArray entries = testcase.get("flags").getAsJsonArray();
    for (int i = 0; i < entries.size(); i++) {
      for (String flag : flags) {
        if (flag.equals(entries.get(i).getAsString())) {
          return true;
        }
      }
    }
    return false;
  }

  private WycheproofTestUtil() {}
}
