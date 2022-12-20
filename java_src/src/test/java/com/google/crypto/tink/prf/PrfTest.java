// Copyright 2022 Google LLC
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

package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for the Prf package. Uses only the public API. */
@RunWith(Theories.class)
public final class PrfTest {

  @BeforeClass
  public static void setUp() throws Exception {
    PrfConfig.register();
    DeterministicAeadConfig.register(); // Needed for getPrimitiveFromNonMacKeyset_throws.
  }

  @DataPoints("templates")
  public static final String[] TEMPLATES =
      new String[] {
        "AES_CMAC_PRF",
        "HMAC_SHA256_PRF",
        "HMAC_SHA512_PRF",
        "HKDF_SHA256",
      };

  @Theory
  public void create_computeVerify(@FromDataPoints("templates") String templateName)
      throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    int primaryId = handle.getPrimary().getId();
    PrfSet prfSet = handle.getPrimitive(PrfSet.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] outputPrimary = prfSet.computePrimary(data, 12);
    byte[] output = prfSet.getPrfs().get(primaryId).compute(data, 12);
    assertThat(output).isEqualTo(outputPrimary);

    int invalidId = primaryId + 1;
    assertThat(prfSet.getPrfs().get(invalidId)).isNull();
  }

  // A keyset with one MAC key, serialized in Tink's JSON format.
  private static final String JSON_PRF_KEYSET =
      ""
          + "{"
          + "  \"primaryKeyId\": 166506972,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.HmacPrfKey\","
          + "        \"value\": \"GkAlMHOHF4em1ax2/xzlhOX9696c6OIuSuYJ//DmzMshOjeGDjVazNZZKXo"
          + "yo+USpExayMyab+GtjOfCCVjsECxnEgIIBA==\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 166506972,"
          + "      \"outputPrefixType\": \"RAW\""
          + "    }"
          + "  ]"
          + "}";

  @Theory
  public void readKeysetEncryptDecrypt()
      throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(JSON_PRF_KEYSET, InsecureSecretKeyAccess.get());
    PrfSet prfSet = handle.getPrimitive(PrfSet.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] output1 = prfSet.computePrimary(data, 12);
    byte[] output2 = prfSet.getPrfs().get(166506972).compute(data, 12);
    assertThat(output2).isEqualTo(output1);
  }

  // A keyset with multiple keys. The first key is the same as in JSON_AEAD_KEYSET.
  private static final String JSON_PRF_KEYSET_WITH_MULTIPLE_KEYS =
      ""
          + "{"
          + "  \"primaryKeyId\": 1781110497,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.HmacPrfKey\","
          + "        \"value\": \"GkAlMHOHF4em1ax2/xzlhOX9696c6OIuSuYJ//DmzMshOjeGDjVazNZZKXo"
          + "yo+USpExayMyab+GtjOfCCVjsECxnEgIIBA==\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 166506972,"
          + "      \"outputPrefixType\": \"RAW\""
          + "    }, {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.HkdfPrfKey\","
          + "        \"value\": \"GiC+cZnHCSh8CGzIoe9/jYhJeyk+vNdVSH+77Rc+BaGNvxICCAM=\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 1781110497,"
          + "      \"outputPrefixType\": \"RAW\""
          + "    },"
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.HmacPrfKey\","
          + "        \"value\": \"GkBO8P7LMfUeCuqUZUY0xiAOi3q7lABfCA81kHv0qowLsjwmYwAa3leo9tD"
          + "ez28gJtnWtghWQ3fVfWsZstNIOw0lEgIIBA==\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 1593211602,"
          + "      \"outputPrefixType\": \"RAW\""
          + "    }"
          + "  ]"
          + "}";

  @Theory
  public void multipleKeysReadKeysetWithEncryptDecrypt()
      throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_PRF_KEYSET_WITH_MULTIPLE_KEYS, InsecureSecretKeyAccess.get());

    PrfSet prfSet = handle.getPrimitive(PrfSet.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] outputPrimary = prfSet.computePrimary(data, 12);

    byte[] output1 = prfSet.getPrfs().get(166506972).compute(data, 12);
    assertThat(output1).isNotEqualTo(outputPrimary);
    byte[] output2 = prfSet.getPrfs().get(1781110497).compute(data, 12);
    assertThat(output2).isEqualTo(outputPrimary);
    byte[] output3 = prfSet.getPrfs().get(1593211602).compute(data, 12);
    assertThat(output3).isNotEqualTo(outputPrimary);

  }

  // A keyset with a valid DeterministicAead key. This keyset can't be used with the Mac primitive.
  private static final String JSON_DAEAD_KEYSET =
      ""
          + "{"
          + "  \"primaryKeyId\": 961932622,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.AesSivKey\","
          + "        \"keyMaterialType\": \"SYMMETRIC\","
          + "        \"value\": \"EkCJ9r5iwc5uxq5ugFyrHXh5dijTa7qalWUgZ8Gf08RxNd545FjtLMYL7ObcaFtCS"
          + "kvV2+7u6F2DN+kqUjAfkf2W\""
          + "      },"
          + "      \"outputPrefixType\": \"TINK\","
          + "      \"keyId\": 961932622,"
          + "      \"status\": \"ENABLED\""
          + "    }"
          + "  ]"
          + "}";

  @Theory
  public void getPrimitiveFromNonMacKeyset_throws() throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(JSON_DAEAD_KEYSET, InsecureSecretKeyAccess.get());
    // Test that the keyset can create a DeterministicAead primitive, but not a Mac.
    Object unused = handle.getPrimitive(DeterministicAead.class);
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(Mac.class));
  }
}
