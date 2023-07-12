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

package com.google.crypto.tink.keyderivation;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.prf.PrfConfig;
import com.google.crypto.tink.prf.PrfParameters;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for the Key Derivation package. Uses only the public API. */
@RunWith(JUnit4.class)
public final class KeyDerivationTest {

  @BeforeClass
  public static void setUp() throws Exception {
    PrfConfig.register();  // Needed for PRF-based key derivation
    AeadConfig.register();  // Needed to derive Aead keys
    MacConfig.register();  // Needed to derive Mac keys
    KeyDerivationConfig.register();
    DeterministicAeadConfig.register(); // Needed for getPrimitiveFromNonKeysetDeriverKeyset_throws.
  }

  @Test
  public void createTemplateAndDeriveAesGcmKeyset_success() throws Exception {
    Assume.assumeFalse(TestUtil.isAndroid()); // some android versions don't support AesGcm
    Parameters keyDerivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters((PrfParameters) KeyTemplates.get("HKDF_SHA256").toParameters())
            .setDerivedKeyParameters(KeyTemplates.get("AES256_GCM").toParameters())
            .build();

    KeysetHandle handle = KeysetHandle.generateNew(keyDerivationParameters);
    KeysetDeriver deriver = handle.getPrimitive(KeysetDeriver.class);

    KeysetHandle derivedHandle = deriver.deriveKeyset("salt".getBytes(UTF_8));

    // Use derived keyset, which should contain an AES256_GCM key.
    Aead aead = derivedHandle.getPrimitive(Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  private static final String JSON_AEAD_KEYSET_DERIVATION_KEYSET = ""
      + "{"
      + "  \"primaryKeyId\": 2494827163,"
      + "  \"key\": ["
      + "    {"
      + "      \"keyData\": {"
      + "        \"typeUrl\":"
      + "\"type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey\","
      + "        \"value\": \"GjoKOBgBEgIQIAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHR"
      + "vLnRpbmsuQWVzR2NtS2V5El0KMXR5cGUuZ29vZ2xlYXBpcy5jb20vZ29vZ2xlLmNyeXB0by50aW5rLkh"
      + "rZGZQcmZLZXkSJhog6TOgPvUUH+iOCewfS5BhSltazMDIGQt3sNEBl1MwFLsSAggDGAE=\","
      + "        \"keyMaterialType\": \"SYMMETRIC\""
      + "      },"
      + "      \"status\": \"ENABLED\","
      + "      \"keyId\": 2494827163,"
      + "      \"outputPrefixType\": \"TINK\""
      + "    }"
      + "  ]"
      + "}";

  @Test
  public void readKeysetAndDeriveAesGcmKeyset_success() throws Exception {
    Assume.assumeFalse(TestUtil.isAndroid()); // some android versions don't support AesGcm
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_AEAD_KEYSET_DERIVATION_KEYSET, InsecureSecretKeyAccess.get());
    KeysetDeriver deriver = handle.getPrimitive(KeysetDeriver.class);

    KeysetHandle derivedHandle = deriver.deriveKeyset("salt".getBytes(UTF_8));

    Aead aead = derivedHandle.getPrimitive(Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  // A keyset with multiple keys. The first key is the same as in JSON_AEAD_KEYSET.
  private static final String JSON_AEAD_KEYSET_DERIVATION_KEYSET_WITH_MULTIPLE_KEYS =
      ""
          + "{"
          + "  \"primaryKeyId\": 1956345672,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\":"
          + "\"type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey\","
          + "        \"value\": \"GjoKOBgBEgIQIAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHR"
          + "vLnRpbmsuQWVzR2NtS2V5El0KMXR5cGUuZ29vZ2xlYXBpcy5jb20vZ29vZ2xlLmNyeXB0by50aW5rLkh"
          + "rZGZQcmZLZXkSJhog6TOgPvUUH+iOCewfS5BhSltazMDIGQt3sNEBl1MwFLsSAggDGAE=\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 2494827163,"
          + "      \"outputPrefixType\": \"TINK\""
          + "    },"
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\":"
          + "\"type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey\","
          + "        \"value\": \"El0KMXR5cGUuZ29vZ2xlYXBpcy5jb20vZ29vZ2xlLmNyeXB0by50aW5rLkh"
          + "rZGZQcmZLZXkSJhICCAMaIK6DXudkRW9O/oHDHRdEDW6WLYm/QpQusLolaceFfYSZGAEaOgo4CjB0eXB"
          + "lLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNHY21LZXkSAhAgGAM=\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 1956345672,"
          + "      \"outputPrefixType\": \"RAW\""
          + "    },"
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\":"
          + "\"type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey\","
          + "        \"value\": \"GjoKOBgBEgIQEAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHR"
          + "vLnRpbmsuQWVzR2NtS2V5El0KMXR5cGUuZ29vZ2xlYXBpcy5jb20vZ29vZ2xlLmNyeXB0by50aW5rLkh"
          + "rZGZQcmZLZXkSJhoggQMOJny+9/MlRAIZohEinWov3jeLHBoJD+hnwTS2TIUSAggDGAE=\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 2901163075,"
          + "      \"outputPrefixType\": \"TINK\""
          + "    }"
          + "  ]"
          + "}";

  @Test
  public void multipleKeysReadKeysetAndDeriveAesGcmKeyset_success() throws Exception {
    Assume.assumeFalse(TestUtil.isAndroid()); // some android versions don't support AesGcm
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_AEAD_KEYSET_DERIVATION_KEYSET_WITH_MULTIPLE_KEYS, InsecureSecretKeyAccess.get());
    KeysetDeriver deriver = handle.getPrimitive(KeysetDeriver.class);

    KeysetHandle derivedHandle = deriver.deriveKeyset("salt".getBytes(UTF_8));

    // Derived keyset should only contain AEAD keys
    Aead aead = derivedHandle.getPrimitive(Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);

    // Also test that aead can decrypt messages encrypted with keyset derived from a non-primary
    // key. Use JSON_AEAD_KEYSET_DERIVATION_KEYSET, because it contains the first key from
    // JSON_AEAD_KEYSET_DERIVATION_KEYSET_WITH_MULTIPLE_KEYS.
    KeysetHandle handle1 =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_AEAD_KEYSET_DERIVATION_KEYSET, InsecureSecretKeyAccess.get());
    KeysetDeriver deriver1 = handle1.getPrimitive(KeysetDeriver.class);
    KeysetHandle derivedHandle1 = deriver1.deriveKeyset("salt".getBytes(UTF_8));
    Aead aead1 = derivedHandle1.getPrimitive(Aead.class);
    byte[] ciphertext1 = aead1.encrypt(plaintext, associatedData);
    assertThat(aead.decrypt(ciphertext1, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void createTemplateAndDeriveHmacKeyset_success() throws Exception {
    Parameters keyDerivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters((PrfParameters) KeyTemplates.get("HKDF_SHA256").toParameters())
            .setDerivedKeyParameters(KeyTemplates.get("HMAC_SHA256_128BITTAG").toParameters())
            .build();

    KeysetHandle handle = KeysetHandle.generateNew(keyDerivationParameters);
    KeysetDeriver deriver = handle.getPrimitive(KeysetDeriver.class);

    KeysetHandle derivedHandle = deriver.deriveKeyset("salt".getBytes(UTF_8));

    // Use derived keyset, which should contain an HMAC key.
    Mac mac = derivedHandle.getPrimitive(Mac.class);
    byte[] data = "data".getBytes(UTF_8);
    byte[] tag = mac.computeMac(data);
    mac.verifyMac(tag, data);
  }

  private static final String JSON_MAC_KEYSET_DERIVATION_KEYSET = ""
      + "{"
      + "  \"primaryKeyId\": 104819069,"
      + "  \"key\": ["
      + "    {"
      + "      \"keyData\": {"
      + "        \"typeUrl\":"
      + "\"type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey\","
      + "        \"value\": \"El0KMXR5cGUuZ29vZ2xlYXBpcy5jb20vZ29vZ2xlLmNyeXB0by50aW5rLkh"
      + "rZGZQcmZLZXkSJhICCAMaIOlSI9lmjAIyFTOEUUt2DqEdjSFCt+yFJDp5Z7/+h6tKGAEaPgo8Ci50eXB"
      + "lLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5IbWFjS2V5EggQIAoEEBAIAxgB\","
      + "        \"keyMaterialType\": \"SYMMETRIC\""
      + "      },"
      + "      \"status\": \"ENABLED\","
      + "      \"keyId\": 104819069,"
      + "      \"outputPrefixType\": \"TINK\""
      + "    }"
      + "  ]"
      + "}";

  @Test
  public void readKeysetAndDeriveHmacKeyset_success() throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_MAC_KEYSET_DERIVATION_KEYSET, InsecureSecretKeyAccess.get());
    KeysetDeriver deriver = handle.getPrimitive(KeysetDeriver.class);

    KeysetHandle derivedHandle = deriver.deriveKeyset("salt".getBytes(UTF_8));

    // Use derived keyset, which should contain an HMAC key.
    Mac mac = derivedHandle.getPrimitive(Mac.class);
    byte[] data = "data".getBytes(UTF_8);
    byte[] tag = mac.computeMac(data);
    mac.verifyMac(tag, data);
  }

  // A keyset with a valid DeterministicAead key. This keyset can't be used with the KeysetDeriver
  // primitive.
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

  @Test
  public void getPrimitiveFromNonKeysetDeriverKeyset_throws() throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(JSON_DAEAD_KEYSET, InsecureSecretKeyAccess.get());
    // Test that the keyset can create a DeterministicAead primitive, but not a KeysetDeriver.
    Object unused = handle.getPrimitive(DeterministicAead.class);
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(KeysetDeriver.class));
  }
}
