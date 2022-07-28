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

package com.google.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for the Aead package. Uses only the public API. */
@RunWith(Theories.class)
public final class AeadTest {

  @BeforeClass
  public static void setUp() throws Exception {
    AeadConfig.register();
    DeterministicAeadConfig.register(); // Needed for getPrimitiveFromNonAeadKeyset_throws.
  }

  @DataPoints("templates")
  public static final String[] TEMPLATES =
      new String[] {
        "AES128_EAX",
        "AES128_EAX_RAW",
        "AES256_EAX",
        "AES256_EAX_RAW",
        "AES128_GCM",
        "AES128_GCM_RAW",
        "AES256_GCM",
        "AES256_GCM_RAW",
        "AES128_CTR_HMAC_SHA256",
        "AES128_CTR_HMAC_SHA256_RAW",
        "AES256_CTR_HMAC_SHA256",
        "AES256_CTR_HMAC_SHA256_RAW",
        "CHACHA20_POLY1305",
        "CHACHA20_POLY1305_RAW",
        "XCHACHA20_POLY1305",
        "XCHACHA20_POLY1305_RAW"
      };

  @Theory
  public void createEncryptDecrypt(@FromDataPoints("templates") String templateName)
      throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    Aead aead = handle.getPrimitive(Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);

    KeysetHandle otherHandle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    Aead otherAead = otherHandle.getPrimitive(Aead.class);
    assertThrows(
        GeneralSecurityException.class, () -> otherAead.decrypt(ciphertext, associatedData));

    byte[] invalid = "invalid".getBytes(UTF_8);
    byte[] empty = "".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, invalid));
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(invalid, associatedData));
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(empty, associatedData));
    assertThat(aead.decrypt(aead.encrypt(empty, associatedData), associatedData)).isEqualTo(empty);
    assertThat(aead.decrypt(aead.encrypt(plaintext, empty), empty)).isEqualTo(plaintext);
  }

  // A keyset with one AEAD key, serialized in Tink's JSON format.
  private static final String JSON_AEAD_KEYSET =
      ""
          + "{"
          + "  \"primaryKeyId\": 42818733,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.AesGcmKey\","
          + "        \"keyMaterialType\": \"SYMMETRIC\","
          + "        \"value\": \"GhCC74uJ+2f4qlpaHwR4ylNQ\""
          + "      },"
          + "      \"outputPrefixType\": \"TINK\","
          + "      \"keyId\": 42818733,"
          + "      \"status\": \"ENABLED\""
          + "    }"
          + "  ]"
          + "}";

  @Theory
  public void readKeysetEncryptDecrypt()
      throws Exception {
    KeysetHandle handle = CleartextKeysetHandle.read(JsonKeysetReader.withString(JSON_AEAD_KEYSET));

    Aead aead = handle.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  // A keyset with multiple keys. The first key is the same as in JSON_AEAD_KEYSET.
  private static final String JSON_AEAD_KEYSET_WITH_MULTIPLE_KEYS =
      ""
          + "{"
          + "  \"primaryKeyId\": 365202604,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.AesGcmKey\","
          + "        \"keyMaterialType\": \"SYMMETRIC\","
          + "        \"value\": \"GhCC74uJ+2f4qlpaHwR4ylNQ\""
          + "      },"
          + "      \"outputPrefixType\": \"TINK\","
          + "      \"keyId\": 42818733,"
          + "      \"status\": \"ENABLED\""
          + "    }, {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.AesEaxKey\","
          + "        \"keyMaterialType\": \"SYMMETRIC\","
          + "        \"value\": \"EgIIEBogU4nieBfIeJHBrhC+TjezFgxkkuhQHbyWkUMH+7atLxI=\""
          + "      },"
          + "      \"outputPrefixType\": \"RAW\","
          + "      \"keyId\": 365202604,"
          + "      \"status\": \"ENABLED\""
          + "    }, {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey\","
          + "        \"keyMaterialType\": \"SYMMETRIC\","
          + "        \"value\": \"GigaIMttlipP/JvQOpIB0NYhDPoLgWBiIxmtaWbSPa2TeQOmEgQQEAgDEhYaEPcCM"
          + "mPLgRGhmMmSC4AJ1CESAggQ\""
          + "      },"
          + "      \"outputPrefixType\": \"LEGACY\","
          + "      \"keyId\": 277095770,"
          + "      \"status\": \"ENABLED\""
          + "    }"
          + "  ]"
          + "}";

  @Theory
  public void multipleKeysReadKeysetWithEncryptDecrypt()
      throws Exception {
    KeysetHandle handle =
        CleartextKeysetHandle.read(
            JsonKeysetReader.withString(JSON_AEAD_KEYSET_WITH_MULTIPLE_KEYS));

    Aead aead = handle.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);

    // Also test that aead can decrypt ciphertexts encrypted with a non-primary key. We use
    // JSON_AEAD_KEYSET to encrypt with the first key.
    KeysetHandle handle1 =
        CleartextKeysetHandle.read(JsonKeysetReader.withString(JSON_AEAD_KEYSET));
    Aead aead1 = handle1.getPrimitive(Aead.class);
    byte[] ciphertext1 = aead1.encrypt(plaintext, associatedData);
    assertThat(aead.decrypt(ciphertext1, associatedData)).isEqualTo(plaintext);
  }

  // A keyset with a valid DeterministicAead key. This keyset can't be used with the Aead primitive.
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
  public void getPrimitiveFromNonAeadKeyset_throws()
      throws Exception {
    KeysetHandle handle =
        CleartextKeysetHandle.read(
            JsonKeysetReader.withString(JSON_DAEAD_KEYSET));
    // Test that the keyset can create a DeterministicAead primitive, but not a Aead.
    handle.getPrimitive(DeterministicAead.class);
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(Aead.class));
  }
}
