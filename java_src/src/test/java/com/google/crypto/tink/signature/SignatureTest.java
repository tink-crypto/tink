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

package com.google.crypto.tink.signature;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for the Signature package. Uses only the public API. */
@RunWith(Theories.class)
public final class SignatureTest {

  @BeforeClass
  public static void setUp() throws Exception {
    SignatureConfig.register();
    DeterministicAeadConfig.register(); // Needed for getPrimitiveFromNonSignatureKeyset_throws.
  }

  @DataPoints("templates")
  public static final String[] TEMPLATES =
      new String[] {
        // Only use one key template from the RSA key managers because key generation is slow.
        "RSA_SSA_PKCS1_3072_SHA256_F4",
        "RSA_SSA_PSS_3072_SHA256_F4",
        "ECDSA_P256",
        "ECDSA_P256_RAW",
        "ECDSA_P384_SHA384",
        "ECDSA_P384_SHA512",
        "ECDSA_P521",
        "ED25519",
        "ED25519_RAW",
      };

  @Theory
  public void createSignVerify(@FromDataPoints("templates") String templateName)
      throws Exception {
    if (TestUtil.isTsan()) {
      // KeysetHandle.generateNew is too slow in Tsan.
      return;
    }
    KeysetHandle privateHandle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    PublicKeySign signer = privateHandle.getPrimitive(PublicKeySign.class);
    PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);
    verifier.verify(sig, data);

    KeysetHandle otherPrivateHandle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    PublicKeyVerify otherVerifier =
        otherPrivateHandle.getPublicKeysetHandle().getPrimitive(PublicKeyVerify.class);
    assertThrows(
        GeneralSecurityException.class, () -> otherVerifier.verify(sig, data));

    byte[] invalid = "invalid".getBytes(UTF_8);
    byte[] empty = "".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> verifier.verify(sig, invalid));
    assertThrows(GeneralSecurityException.class, () -> verifier.verify(invalid, data));
    assertThrows(GeneralSecurityException.class, () -> verifier.verify(empty, data));
    verifier.verify(signer.sign(empty), empty);
  }

  // Keyset with one private key for PublicKeySign, serialized in Tink's JSON format.
  private static final String JSON_PRIVATE_KEYSET = ""
      + "{"
      + "  \"primaryKeyId\": 775870498,"
      + "  \"key\": ["
      + "    {"
      + "      \"keyData\": {"
      + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.EcdsaPrivateKey\","
      + "        \"value\": \"GiA/E6s6KksNXrEd9hLdStvhsmdsONgpSODH/rZsBbBDehJMIiApA+NmYiv"
      + "xRfhMuvTKZAwqETmn+WagBP/reucEjEvXkRog1AJ5GBzf+n27xnj9KcoGllF9NIFfQrDEP99FNH+Cne4"
      + "SBhgCEAIIAw==\","
      + "        \"keyMaterialType\": \"ASYMMETRIC_PRIVATE\""
      + "      },"
      + "      \"status\": \"ENABLED\","
      + "      \"keyId\": 775870498,"
      + "      \"outputPrefixType\": \"TINK\""
      + "    }"
      + "  ]"
      + "}";

  // Keyset with the corresponding public key for PublicKeyVerify, serialized in Tink's JSON format.
  private static final String JSON_PUBLIC_KEYSET = ""
      + "{"
      + "  \"primaryKeyId\": 775870498,"
      + "  \"key\": ["
      + "    {"
      + "      \"keyData\": {"
      + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.EcdsaPublicKey\","
      + "        \"value\": \"IiApA+NmYivxRfhMuvTKZAwqETmn+WagBP/reucEjEvXkRog1AJ5GBzf+n2"
      + "7xnj9KcoGllF9NIFfQrDEP99FNH+Cne4SBhgCEAIIAw==\","
      + "        \"keyMaterialType\": \"ASYMMETRIC_PUBLIC\""
      + "      },"
      + "      \"status\": \"ENABLED\","
      + "      \"keyId\": 775870498,"
      + "      \"outputPrefixType\": \"TINK\""
      + "    }"
      + "  ]"
      + "}";

  @Theory
  public void readKeysetEncryptDecrypt()
      throws Exception {
    KeysetHandle privateHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(JSON_PRIVATE_KEYSET, InsecureSecretKeyAccess.get());
    KeysetHandle publicHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(JSON_PUBLIC_KEYSET, InsecureSecretKeyAccess.get());

    PublicKeySign signer = privateHandle.getPrimitive(PublicKeySign.class);
    PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);
    verifier.verify(sig, data);
  }

  // Keyset with multiple keys. The first key is the same as in JSON_PRIVATE_KEYSET. The second
  // key is the primary key and will be used for signing.
  private static final String JSON_PRIVATE_KEYSET_WITH_MULTIPLE_KEYS =
      ""
          + "{"
          + "  \"primaryKeyId\": 1641152230,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.EcdsaPrivateKey\","
          + "        \"value\": \"GiA/E6s6KksNXrEd9hLdStvhsmdsONgpSODH/rZsBbBDehJMIiApA+NmYiv"
          + "xRfhMuvTKZAwqETmn+WagBP/reucEjEvXkRog1AJ5GBzf+n27xnj9KcoGllF9NIFfQrDEP99FNH+Cne4"
          + "SBhgCEAIIAw==\","
          + "        \"keyMaterialType\": \"ASYMMETRIC_PRIVATE\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 775870498,"
          + "      \"outputPrefixType\": \"TINK\""
          + "    },"
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\":"
          + "\"type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey\","
          + "        \"value\": \"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"
          + "ovVFKpiE5K6MSAggE\","
          + "        \"keyMaterialType\": \"ASYMMETRIC_PRIVATE\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 1641152230,"
          + "      \"outputPrefixType\": \"RAW\""
          + "    },"
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.EcdsaPrivateKey\","
          + "        \"value\": \"GiBCX+pnT5vwku4z7jfD4OTgvRtft3S4KuYHovWsQrlTPhJMIiAzcsfCVUz"
          + "GZ13oTmMLxBYd8wFM5G+dgCXMeF8tYXayrRogGOzqO4xtS0H4wl/5M/QUkLDnpnmt2TqIiQlFk0vAdck"
          + "SBhgCEAIIAw==\","
          + "        \"keyMaterialType\": \"ASYMMETRIC_PRIVATE\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 857170602,"
          + "      \"outputPrefixType\": \"LEGACY\""
          + "    }"
          + "  ]"
          + "}";

  // Keyset with the public keys of the keys from JSON_PRIVATE_KEYSET_WITH_MULTIPLE_KEYS.
  private static final String JSON_PUBLIC_KEYSET_WITH_MULTIPLE_KEYS = ""
      + "{"
      + "  \"primaryKeyId\": 1641152230,"
      + "  \"key\": ["
      + "    {"
      + "      \"keyData\": {"
      + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.EcdsaPublicKey\","
      + "        \"value\": \"IiApA+NmYivxRfhMuvTKZAwqETmn+WagBP/reucEjEvXkRog1AJ5GBzf+n2"
      + "7xnj9KcoGllF9NIFfQrDEP99FNH+Cne4SBhgCEAIIAw==\","
      + "        \"keyMaterialType\": \"ASYMMETRIC_PUBLIC\""
      + "      },"
      + "      \"status\": \"ENABLED\","
      + "      \"keyId\": 775870498,"
      + "      \"outputPrefixType\": \"TINK\""
      + "    },"
      + "    {"
      + "      \"keyData\": {"
      + "        \"typeUrl\":"
      + "\"type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey\","
      + "        \"value\": \"IgMBAAEagATs8xew2XBre4TqIOeaGagCvO6DOaclGHK0HNwvh0aGsg4zBCd"
      + "xoc18M+xNbJ+MuFrpDRN8E+IMabQGr78jKBAzdYqh9Ue4fYnv5u3halLQBFJBuV9eJdrO9gAPiPgtW0E"
      + "T5O4HJsYH+dra6L8bjzjnaKn4UblXsbqwR+TGKzcROBm3JMHqgMNddrKYygaWJway5zroFY9GKSjg6+d"
      + "Lw9GmLTKht3DrmC2CAOusP8ZLgf4VWrWQQ6tUoULhRlljJqKZieXkhLU70/PW+bl6mJxam0Wh0AWjk3Q"
      + "LMr+HDByhxvTYK5SDE42tLdnKnD4bHIx2BEjY/8KmKGbtRII7M3GMcSY2C3ta7C1AKFzhkR2VnUpcVdc"
      + "QFl/qHAs0qTkmHsw6Yl8xJT0v0nVOqSt+WzbrxPQURSYPSdyItEeh6qNoP1xbFqHz0XqvVS4Kj4tWxCn"
      + "jLuD+pebFS8u8VHok9nAfH2LJNtUR7nj8/ZtyBu20QhiOqCzkUu3Vwbp2qMqIXGULxItkmwyDXGlk1NV"
      + "7uOnNfU63ScrzJj9SYtSuCrQAcffU3cv1ru+Dq/+4jmR1ZlmgBKMGVXMs2B4EKhAZfAV1M0Q14NgIBZc"
      + "SA7rkrWG6rdRygmOO8JMPS2Wt1M1fur3XlNLd7j3GAlPeUHhPKcCjYWCz051m1qi9UUqmITkroxICCAQ"
      + "=\","
      + "        \"keyMaterialType\": \"ASYMMETRIC_PUBLIC\""
      + "      },"
      + "      \"status\": \"ENABLED\","
      + "      \"keyId\": 1641152230,"
      + "      \"outputPrefixType\": \"RAW\""
      + "    },"
      + "    {"
      + "      \"keyData\": {"
      + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.EcdsaPublicKey\","
      + "        \"value\": \"IiAzcsfCVUzGZ13oTmMLxBYd8wFM5G+dgCXMeF8tYXayrRogGOzqO4xtS0H"
      + "4wl/5M/QUkLDnpnmt2TqIiQlFk0vAdckSBhgCEAIIAw==\","
      + "        \"keyMaterialType\": \"ASYMMETRIC_PUBLIC\""
      + "      },"
      + "      \"status\": \"ENABLED\","
      + "      \"keyId\": 857170602,"
      + "      \"outputPrefixType\": \"LEGACY\""
      + "    }"
      + "  ]"
      + "}";

  @Theory
  public void multipleKeysReadKeysetWithEncryptDecrypt()
      throws Exception {
    KeysetHandle privateHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_PRIVATE_KEYSET_WITH_MULTIPLE_KEYS, InsecureSecretKeyAccess.get());
    KeysetHandle publicHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_PUBLIC_KEYSET_WITH_MULTIPLE_KEYS, InsecureSecretKeyAccess.get());

    PublicKeySign signer = privateHandle.getPrimitive(PublicKeySign.class);
    PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);
    verifier.verify(sig, data);

    // Also test that verifier can verify signatures of a non-primary key. We use
    // JSON_PRIVATE_KEYSET to sign with the first key.
    KeysetHandle privateHandle1 =
        TinkJsonProtoKeysetFormat.parseKeyset(JSON_PRIVATE_KEYSET, InsecureSecretKeyAccess.get());
    PublicKeySign signer1 = privateHandle1.getPrimitive(PublicKeySign.class);

    byte[] data1 = "data1".getBytes(UTF_8);
    byte[] sig1 = signer1.sign(data1);
    verifier.verify(sig1, data1);
  }

  // A keyset with a valid DeterministicAead key. This keyset can't be used with the PublicKeySign
  // or PublicKeyVerify.
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
  public void getPrimitiveFromNonSignatureKeyset_throws()
      throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_DAEAD_KEYSET, InsecureSecretKeyAccess.get());

    // Test that the keyset can create a DeterministicAead primitive, but neither PublicKeySign
    // nor PublicKeyVerify primitives.
    Object unused = handle.getPrimitive(DeterministicAead.class);
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(PublicKeySign.class));
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(PublicKeyVerify.class));
  }
}
