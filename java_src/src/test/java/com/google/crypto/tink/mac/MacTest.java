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

package com.google.crypto.tink.mac;

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
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for the Mac package. Uses only the public API. */
@RunWith(Theories.class)
public final class MacTest {

  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();
    DeterministicAeadConfig.register(); // Needed for getPrimitiveFromNonMacKeyset_throws.
  }

  @DataPoints("templates")
  public static final String[] TEMPLATES =
      new String[] {
        "AES256_CMAC",
        "AES256_CMAC_RAW",
        "HMAC_SHA256_128BITTAG",
        "HMAC_SHA256_128BITTAG_RAW",
        "HMAC_SHA256_256BITTAG",
        "HMAC_SHA256_256BITTAG_RAW",
        "HMAC_SHA512_128BITTAG",
        "HMAC_SHA512_128BITTAG_RAW",
        "HMAC_SHA512_256BITTAG",
        "HMAC_SHA512_256BITTAG_RAW",
        "HMAC_SHA512_512BITTAG",
        "HMAC_SHA512_512BITTAG_RAW",
      };

  @Theory
  public void create_computeVerify(@FromDataPoints("templates") String templateName)
      throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    Mac mac = handle.getPrimitive(Mac.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] tag = mac.computeMac(data);
    mac.verifyMac(tag, data);

    KeysetHandle otherHandle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    Mac otherMac = otherHandle.getPrimitive(Mac.class);
    assertThrows(GeneralSecurityException.class, () -> otherMac.verifyMac(tag, data));

    byte[] invalid = "invalid".getBytes(UTF_8);
    byte[] empty = "".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(invalid, data));
    assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(tag, invalid));
    assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(empty, data));
    assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(tag, empty));
    mac.verifyMac(mac.computeMac(empty), empty);
  }

  @Theory
  public void useAesCmacParametersAndAesCmacKey() throws Exception {
    AesCmacParameters parameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(13)
            .setVariant(AesCmacParameters.Variant.LEGACY)
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(123).makePrimary())
            .build();

    AesCmacKey aesCmacKey = (AesCmacKey) handle.getAt(0).getKey();
    assertThat(aesCmacKey.getParameters()).isEqualTo(parameters);
    assertThat(aesCmacKey.getIdRequirementOrNull()).isEqualTo(123);
    SecretBytes secretBytes = aesCmacKey.getAesKey();
    assertThat(secretBytes.size()).isEqualTo(32);

    Mac mac = handle.getPrimitive(Mac.class);
    byte[] data = "data".getBytes(UTF_8);
    byte[] tag = mac.computeMac(data);
    mac.verifyMac(tag, data);
  }

  @Theory
  public void useHmacParametersAndHmacKey() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(42)
            .setTagSizeBytes(13)
            .setHashType(HmacParameters.HashType.SHA1)
            .setVariant(HmacParameters.Variant.CRUNCHY)
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(123).makePrimary())
            .build();

    HmacKey hmacKey = (HmacKey) handle.getAt(0).getKey();
    assertThat(hmacKey.getParameters()).isEqualTo(parameters);
    assertThat(hmacKey.getIdRequirementOrNull()).isEqualTo(123);
    SecretBytes secretBytes = hmacKey.getKeyBytes();
    assertThat(secretBytes.size()).isEqualTo(42);

    Mac mac = handle.getPrimitive(Mac.class);
    byte[] data = "data".getBytes(UTF_8);
    byte[] tag = mac.computeMac(data);
    mac.verifyMac(tag, data);
  }

  // A keyset with one MAC key, serialized in Tink's JSON format.
  private static final String JSON_MAC_KEYSET =
      ""
          + "{"
          + "  \"primaryKeyId\": 207420876,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.HmacKey\","
          + "        \"value\": \"GiAPii+kxtLpvCARQpftFLt4R+O6ARsyhTR7SkCCGt0bHRIEEBAIAw==\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 207420876,"
          + "      \"outputPrefixType\": \"TINK\""
          + "    }"
          + "  ]"
          + "}";

  @Theory
  public void readKeysetEncryptDecrypt()
      throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(JSON_MAC_KEYSET, InsecureSecretKeyAccess.get());

    Mac mac = handle.getPrimitive(Mac.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] tag = mac.computeMac(data);
    mac.verifyMac(tag, data);
  }

  // A keyset with multiple keys. The first key is the same as in JSON_AEAD_KEYSET.
  private static final String JSON_MAC_KEYSET_WITH_MULTIPLE_KEYS =
      ""
          + "{"
          + "  \"primaryKeyId\": 2054715504,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.HmacKey\","
          + "        \"value\": \"GiAPii+kxtLpvCARQpftFLt4R+O6ARsyhTR7SkCCGt0bHRIEEBAIAw==\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 207420876,"
          + "      \"outputPrefixType\": \"TINK\""
          + "    }, {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.AesCmacKey\","
          + "        \"value\": \"GgIIEBIgLaZ/6QXYeqZB8F4zHTRJU5k6TF5xvlSX9ZVLVA09UY0=\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 2054715504,"
          + "      \"outputPrefixType\": \"RAW\""
          + "    }, {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.HmacKey\","
          + "        \"value\": \"GkCCIGYpFz3mj8wnTH3Ca81F1sQ7JEMxoE8B2nKiND7LrKfbaUx+/qqDXUP"
          + "VjkzC9XdbjsaEqc9yI+RKyITef+eUEgQQQAgE\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 1540103625,"
          + "      \"outputPrefixType\": \"LEGACY\""
          + "    }, {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.HmacKey\","
          + "        \"value\": \"GkA8u6JKtInsySJDZO4j6TLoIvLuGAeAZHDZoTlST0aZZ8gZZViHogzWTqt"
          + "i2Vlp3ccy+OdN6lhMxSiphcPaR5OiEgQQIAgE\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 570162478,"
          + "      \"outputPrefixType\": \"CRUNCHY\""
          + "    }"
          + "  ]"
          + "}";

  @Theory
  public void multipleKeysReadKeysetWithEncryptDecrypt()
      throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_MAC_KEYSET_WITH_MULTIPLE_KEYS, InsecureSecretKeyAccess.get());

    Mac mac = handle.getPrimitive(Mac.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] tag = mac.computeMac(data);
    mac.verifyMac(tag, data);

    // Also test that mac can verify tags computed with a non-primary key. We use
    // JSON_MAC_KEYSET to compute a tag with the first key.
    KeysetHandle handle1 =
        TinkJsonProtoKeysetFormat.parseKeyset(JSON_MAC_KEYSET, InsecureSecretKeyAccess.get());
    Mac mac1 = handle1.getPrimitive(Mac.class);
    byte[] tag1 = mac1.computeMac(data);
    mac.verifyMac(tag1, data);
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
