// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.testing;

import com.google.crypto.tink.hybrid.internal.HpkeUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Test utility class for HPKE implementation. */
public final class HpkeTestUtil {

  /**
   * Parses JSON-formatted test vectors from {@code path} into a {@link java.util.Map} from {@link
   * com.google.crypto.tink.hybrid.internal.HpkeTestId}s to {@link
   * com.google.crypto.tink.hybrid.internal.HpkeTestVector}s.
   *
   * <p>Example test vectors are available at
   * https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json.
   *
   * @throws IOException if there's an error opening/parsing the file.
   */
  public static Map<HpkeTestId, HpkeTestVector> parseTestVectors(Reader reader) throws IOException {
    Map<HpkeTestId, HpkeTestVector> testVectors = new HashMap<>();
    JsonArray testArray = JsonParser.parseReader(reader).getAsJsonArray();
    for (JsonElement testElement : testArray) {
      JsonObject testObject = testElement.getAsJsonObject();
      HpkeTestId testId =
          new HpkeTestId(
              testObject.get("mode").getAsInt(),
              testObject.get("kem_id").getAsInt(),
              testObject.get("kdf_id").getAsInt(),
              testObject.get("aead_id").getAsInt());
      // Filter out test vectors for unsupported modes and/or KEMs.
      if (Arrays.equals(testId.mode, HpkeUtil.BASE_MODE)
          && Arrays.equals(testId.kemId, HpkeUtil.X25519_HKDF_SHA256_KEM_ID)) {
        HpkeTestSetup testSetup =
            new HpkeTestSetup(
                testObject.get("info").getAsString(),
                testObject.get("skEm").getAsString(),
                testObject.get("pkRm").getAsString(),
                testObject.get("skRm").getAsString(),
                testObject.get("enc").getAsString(),
                testObject.get("shared_secret").getAsString(),
                testObject.get("key").getAsString(),
                testObject.get("base_nonce").getAsString());
        JsonArray encryptionsArray = testObject.get("encryptions").getAsJsonArray();
        List<HpkeTestEncryption> testEncryptions = new ArrayList<>();
        for (JsonElement encryptionElement : encryptionsArray) {
          JsonObject encryptionObject = encryptionElement.getAsJsonObject();
          HpkeTestEncryption testEncryption =
              new HpkeTestEncryption(
                  testSetup.baseNonce,
                  encryptionObject.get("plaintext").getAsString(),
                  encryptionObject.get("aad").getAsString(),
                  encryptionObject.get("nonce").getAsString(),
                  encryptionObject.get("ciphertext").getAsString());
          testEncryptions.add(testEncryption);
        }
        testVectors.put(testId, new HpkeTestVector(testId, testSetup, testEncryptions));
      }
    }
    return testVectors;
  }

  private HpkeTestUtil() {}
}
