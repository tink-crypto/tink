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

package com.google.crypto.tink.daead;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for the Daead package. Uses only the public API. */
@RunWith(Theories.class)
public final class DaeadTest {

  @BeforeClass
  public static void setUp() throws Exception {
    DeterministicAeadConfig.register();
    AeadConfig.register(); // Needed for getPrimitiveFromNonDeterministicAeadKeyset_throws.
  }

  @Test
  public void createEncryptDecryptDeterministically()
      throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("AES256_SIV"));
    DeterministicAead daead = handle.getPrimitive(DeterministicAead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
    byte[] decrypted = daead.decryptDeterministically(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);

    assertThat(daead.encryptDeterministically(plaintext, associatedData)).isEqualTo(ciphertext);

    KeysetHandle otherHandle = KeysetHandle.generateNew(KeyTemplates.get("AES256_SIV"));
    DeterministicAead otherAead = otherHandle.getPrimitive(DeterministicAead.class);
    assertThrows(
        GeneralSecurityException.class,
        () -> otherAead.decryptDeterministically(ciphertext, associatedData));

    byte[] invalid = "invalid".getBytes(UTF_8);
    byte[] empty = "".getBytes(UTF_8);
    assertThrows(
        GeneralSecurityException.class, () -> daead.decryptDeterministically(ciphertext, invalid));
    assertThrows(
        GeneralSecurityException.class,
        () -> daead.decryptDeterministically(invalid, associatedData));
    assertThrows(
        GeneralSecurityException.class,
        () -> daead.decryptDeterministically(empty, associatedData));
    assertThat(
            daead.decryptDeterministically(
                daead.encryptDeterministically(empty, associatedData), associatedData))
        .isEqualTo(empty);
    assertThat(
            daead.decryptDeterministically(daead.encryptDeterministically(plaintext, empty), empty))
        .isEqualTo(plaintext);
  }

  // A keyset with one AEAD key, serialized in Tink's JSON format.
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
  public void readKeyset_EncryptDecryptDeterministically_success()
      throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(JSON_DAEAD_KEYSET, InsecureSecretKeyAccess.get());

    DeterministicAead daead = handle.getPrimitive(DeterministicAead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
    byte[] decrypted = daead.decryptDeterministically(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  // A keyset with multiple keys. The first key is the same as in JSON_AEAD_KEYSET.
  private static final String JSON_DAEAD_KEYSET_WITH_MULTIPLE_KEYS =
      ""
          + "{"
          + "  \"primaryKeyId\": 385749617,"
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
          + "    }, {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.AesSivKey\","
          + "        \"value\": \"EkCGjyLCW8IOilSjFtkBOvpQoOA8ZsCAsFnCawU9ySiii3KefQkY4pGZcdl"
          + "wJypOZem1/L+wPthYeCo4xmdq68hl\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 385749617,"
          + "      \"outputPrefixType\": \"RAW\""
          + "    }, {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.AesSivKey\","
          + "        \"value\": \"EkCCo6EJBokVl3uTcZMA5iCtQArJliOlBBBfjmZ+IHdLGCatgWJ/tsUi2cm"
          + "pw0o3yXyJaJbyT06kUCEP+GvFIjCQ\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 919668303,"
          + "      \"outputPrefixType\": \"LEGACY\""
          + "    }"
          + "  ]"
          + "}";

  @Theory
  public void multipleKeysReadKeyset_encryptDecryptDeterministically_success()
      throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_DAEAD_KEYSET_WITH_MULTIPLE_KEYS, InsecureSecretKeyAccess.get());

    DeterministicAead daead = handle.getPrimitive(DeterministicAead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
    assertThat(daead.decryptDeterministically(ciphertext, associatedData)).isEqualTo(plaintext);

    // Also test that daead can decrypt ciphertexts encrypted with a non-primary key. We use
    // JSON_DAEAD_KEYSET to encrypt with the first key.
    KeysetHandle handle1 =
        TinkJsonProtoKeysetFormat.parseKeyset(JSON_DAEAD_KEYSET, InsecureSecretKeyAccess.get());
    DeterministicAead daead1 = handle1.getPrimitive(DeterministicAead.class);
    byte[] ciphertext1 = daead1.encryptDeterministically(plaintext, associatedData);
    assertThat(daead.decryptDeterministically(ciphertext1, associatedData)).isEqualTo(plaintext);
  }

  // A keyset with a valid Aead key. This keyset can't be used with the DeterministicAead primitive.
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
  public void getPrimitiveFromNonDeterministicAeadKeyset_throws() throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(JSON_AEAD_KEYSET, InsecureSecretKeyAccess.get());
    // Test that the keyset can create a Aead primitive, but not a DeterministicAead.
    Object unused = handle.getPrimitive(Aead.class);
    assertThrows(
        GeneralSecurityException.class, () -> handle.getPrimitive(DeterministicAead.class));
  }
}
