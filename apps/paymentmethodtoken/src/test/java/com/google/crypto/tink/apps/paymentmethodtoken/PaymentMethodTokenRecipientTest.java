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

package com.google.crypto.tink.apps.paymentmethodtoken;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@code PaymentMethodTokenRecipient}. */
@RunWith(JUnit4.class)
public class PaymentMethodTokenRecipientTest {

  /**
   * Sample merchant public key.
   *
   * <p>Corresponds to public key of {@link #MERCHANT_PRIVATE_KEY_PKCS8_BASE64}
   *
   * <p>Created with:
   *
   * <pre>
   * openssl ec -in merchant-key.pem -pubout -text -noout 2> /dev/null | grep "pub:" -A5 \
   *     | xxd -r -p | base64
   * </pre>
   */
  private static final String MERCHANT_PUBLIC_KEY_BASE64 =
      "BOdoXP+9Aq473SnGwg3JU1aiNpsd9vH2ognq4PtDtlLGa3Kj8TPf+jaQNPyDSkh3JUhiS0KyrrlWhAgNZKHYF2Y=";

  /**
   * Sample merchant private key.
   *
   * <p>Corresponds to the private key of {@link #MERCHANT_PUBLIC_KEY_BASE64}
   *
   * <pre>
   * openssl pkcs8 -topk8 -inform PEM -outform PEM -in merchant-key.pem -nocrypt
   * </pre>
   */
  private static final String MERCHANT_PRIVATE_KEY_PKCS8_BASE64 =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjj"
          + "chHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx"
          + "9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm";

  /** An alternative merchant private key used during the tests. */
  private static final String ALTERNATE_MERCHANT_PRIVATE_KEY_PKCS8_BASE64 =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOUIzccyJ3rTx6SVm"
          + "XrWdtwUP0NU26nvc8KIYw2GmYZKhRANCAAR5AjmTNAE93hQEQE+PryLlgr6Q7FXyN"
          + "XoZRk+1Fikhq61mFhQ9s14MOwGBxd5O6Jwn/sdUrWxkYk3idtNEN1Rz";

  /** Sample Google provided JSON with its public signing keys. */
  private static final String GOOGLE_VERIFYING_PUBLIC_KEYS_JSON =
      "{\n"
          + "  \"keys\": [\n"
          + "    {\n"
          + "      \"keyValue\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPYnHwS8uegWAewQtlxizmLFynw"
          + "HcxRT1PK07cDA6/C4sXrVI1SzZCUx8U8S0LjMrT6ird/VW7be3Mz6t/srtRQ==\",\n"
          + "      \"protocolVersion\": \"ECv1\"\n"
          + "    },\n"
          + "    {\n"
          + "      \"keyValue\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM"
          + "43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==\",\n"
          + "      \"keyExpiration\": \""
          + Instant.now().plus(Duration.standardDays(1)).getMillis()
          + "\",\n"
          + "      \"protocolVersion\": \"ECv2\"\n"
          + "    },\n"
          + "    {\n"
          + "      \"keyValue\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENXvYqxD5WayKYhuXQevdGdLA8i"
          + "fV4LsRS2uKvFo8wwyiwgQHB9DiKzG6T/P1Fu9Bl7zWy/se5Dy4wk1mJoPuxg==\",\n"
          + "      \"keyExpiration\": \""
          + Instant.now().plus(Duration.standardDays(1)).getMillis()
          + "\",\n"
          + "      \"protocolVersion\": \"ECv2SigningOnly\"\n"
          + "    }\n"
          + "  ]\n"
          + "}";

  /** Index within {@link #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON} of the ECv1 Google signing key. */
  private static final int INDEX_OF_GOOGLE_SIGNING_EC_V1 = 0;

  /** Index within {@link #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON} of the ECv2 Google signing key. */
  private static final int INDEX_OF_GOOGLE_SIGNING_EC_V2 = 1;

  /**
   * Index within {@link #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON} of the ECv2SigningOnly Google signing
   * key.
   */
  private static final int INDEX_OF_GOOGLE_SIGNING_EC_V2_SIGNING_ONLY = 2;

  /**
   * Sample Google private signing key for the ECv1 protocolVersion.
   *
   * <p>Corresponds to the ECv1 private key of the key in {@link
   * #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON}.
   */
  private static final String GOOGLE_SIGNING_EC_V1_PRIVATE_KEY_PKCS8_BASE64 =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZj/Dldxz8fvKVF5O"
          + "TeAtK6tY3G1McmvhMppe6ayW6GahRANCAAQ9icfBLy56BYB7BC2XGLOYsXKfAdzF"
          + "FPU8rTtwMDr8LixetUjVLNkJTHxTxLQuMytPqKt39Vbtt7czPq3+yu1F";

  /**
   * Sample Google private signing key for the ECv2 protocolVersion.
   *
   * <p>Corresponds to ECv2 private key of the key in {@link #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON}.
   */
  private static final String GOOGLE_SIGNING_EC_V2_PRIVATE_KEY_PKCS8_BASE64 =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKvEdSS8f0mjTCNKev"
          + "aKXIzfNC5b4A104gJWI9TsLIMqhRANCAAT/X7ccFVJt2/6Ps1oCt2AzKhIAz"
          + "jfJHJ3Op2DVPGh1LMD3oOPgxzUSIqujHG6dq9Ui93Eacl4VWJPMW/MVHHIL";

  /**
   * Sample Google intermediate public signing key for the ECv2 protocolVersion.
   *
   * <p>Base64 version of the public key encoded in ASN.1 type SubjectPublicKeyInfo defined in the
   * X.509 standard.
   *
   * <p>The intermediate public key will be signed by {@link
   * #GOOGLE_SIGNING_EC_V2_PRIVATE_KEY_PKCS8_BASE64}.
   */
  private static final String GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PUBLIC_KEY_X509_BASE64 =
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yR"
          + "ydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==";

  /**
   * Sample Google intermediate private signing key for the ECv2 protocolVersion.
   *
   * <p>Corresponds to private key of the key in {@link
   * #GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PUBLIC_KEY_X509_BASE64}.
   */
  private static final String GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PRIVATE_KEY_PKCS8_BASE64 =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKvEdSS8f0mjTCNKev"
          + "aKXIzfNC5b4A104gJWI9TsLIMqhRANCAAT/X7ccFVJt2/6Ps1oCt2AzKhIAz"
          + "jfJHJ3Op2DVPGh1LMD3oOPgxzUSIqujHG6dq9Ui93Eacl4VWJPMW/MVHHIL";

  /**
   * Sample Google private signing key for the ECv2SigningOnly protocolVersion.
   *
   * <p>Corresponds to ECv2SigningOnly private key of the key in {@link
   * #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON}.
   */
  private static final String GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_PRIVATE_KEY_PKCS8_BASE64 =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRi9hSdY+knJ08odnY"
          + "tZFMRi7ZYeMoasAijLhD4GiQ1yhRANCAAQ1e9irEPlZrIpiG5dB690Z0sDy"
          + "J9XguxFLa4q8WjzDDKLCBAcH0OIrMbpP8/UW70GXvNbL+x7kPLjCTWYmg+7G";

  /**
   * Sample Google intermediate public signing key for the ECv2SigningOnly protocolVersion.
   *
   * <p>Base64 version of the public key encoded in ASN.1 type SubjectPublicKeyInfo defined in the
   * X.509 standard.
   *
   * <p>The intermediate public key will be signed by {@link
   * #GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_PRIVATE_KEY_PKCS8_BASE64}.
   */
  private static final String
      GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_INTERMEDIATE_PUBLIC_KEY_X509_BASE64 =
          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8OaurwvbyYm8JWDgFPRTIDg0/"
              + "kcQTFAQ4txi5IP0AyM1QiagwRhDUfjpqZkpw8xt/DXwyWYM0DdHqoeV"
              + "TKqmYQ==";

  /**
   * Sample Google intermediate private signing key for the ECv2SigningOnly protocolVersion.
   *
   * <p>Corresponds to private key of the key in {@link
   * #GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_INTERMEDIATE_PUBLIC_KEY_X509_BASE64}.
   */
  private static final String
      GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_INTERMEDIATE_PRIVATE_KEY_PKCS8_BASE64 =
          "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+Jvpkq26tpZ0s"
              + "TTZVh4teEI41SnJdmkBzM8VZ5ZirE2hRANCAATw5q6vC9vJibwlYOAU"
              + "9FMgODT+RxBMUBDi3GLkg/QDIzVCJqDBGENR+OmpmSnDzG38NfDJZgz"
              + "QN0eqh5VMqqZh";

  private static final String RECIPIENT_ID = "someRecipient";

  private static final String PLAINTEXT = "plaintext";

  /**
   * The result of {@link #PLAINTEXT} encrypted with {@link #MERCHANT_PRIVATE_KEY_PKCS8_BASE64} and
   * signed with the only key in {@link #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON} using the ECv1
   * protocolVersion.
   */
  private static final String CIPHERTEXT_EC_V1 =
      "{"
          + "\"protocolVersion\":\"ECv1\","
          + "\"signedMessage\":"
          + ("\"{"
              + "\\\"tag\\\":\\\"ZVwlJt7dU8Plk0+r8rPF8DmPTvDiOA1UAoNjDV+SqDE\\\\u003d\\\","
              + "\\\"ephemeralPublicKey\\\":\\\"BPhVspn70Zj2Kkgu9t8+ApEuUWsI/zos5whGCQBlgOkuYagOis7"
              + "qsrcbQrcprjvTZO3XOU+Qbcc28FSgsRtcgQE\\\\u003d\\\","
              + "\\\"encryptedMessage\\\":\\\"12jUObueVTdy\\\"}\",")
          + "\"signature\":\"MEQCIDxBoUCoFRGReLdZ/cABlSSRIKoOEFoU3e27c14vMZtfAiBtX3pGMEpnw6mSAbnagC"
          + "CgHlCk3NcFwWYEyxIE6KGZVA\\u003d\\u003d\"}";

  private static final String ALTERNATE_PUBLIC_SIGNING_KEY =
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEU8E6JppGKFG40r5dDU1idHRN52NuwsemFzXZh1oUqh3bGUPgPioH+RoW"
          + "nmVSUQz1WfM2426w9f0GADuXzpUkcw==";

  private static final class MyPaymentMethodTokenRecipientKem
      implements PaymentMethodTokenRecipientKem {
    private final ECPrivateKey privateKey;

    public MyPaymentMethodTokenRecipientKem(String recipientPrivateKey)
        throws GeneralSecurityException {
      privateKey = PaymentMethodTokenUtil.pkcs8EcPrivateKey(recipientPrivateKey);
    }

    @Override
    public byte[] computeSharedSecret(final byte[] ephemeralPublicKey)
        throws GeneralSecurityException {
      ECPublicKey publicKey =
          EllipticCurves.getEcPublicKey(
              privateKey.getParams(),
              PaymentMethodTokenConstants.UNCOMPRESSED_POINT_FORMAT,
              ephemeralPublicKey);
      return EllipticCurves.computeSharedSecret(privateKey, publicKey);
    }
  }

  @Test
  public void testShouldDecryptECV1() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(CIPHERTEXT_EC_V1));
  }

  @Test
  public void testShouldDecryptECV1WithNonStrictJsonEncoding() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

  String ciphertextEcV1WithNonStrictJsonEncoding =
      "{"
          + "# comment \n"   // python-style comment terminated with new line
          + "protocolVersion:'ECv1',"   // protocolVersion has no quotes, ECv1 has single quotes
          + "/* a comment */"   // c-style comment
          + "\"signedMessage\"="  // use = instead of :
          + "// another comment \n"   // c-style comment terminated with new line
          + ("\"{"
              + "\\\"tag\\\":\\\"ZVwlJt7dU8Plk0+r8rPF8DmPTvDiOA1UAoNjDV+SqDE\\\\u003d\\\","
              + "\\\"ephemeralPublicKey\\\":\\\"BPhVspn70Zj2Kkgu9t8+ApEuUWsI/zos5whGCQBlgOkuYagOis7"
              + "qsrcbQrcprjvTZO3XOU+Qbcc28FSgsRtcgQE\\\\u003d\\\","
              + "\\\"encryptedMessage\\\":\\\"12jUObueVTdy\\\"}\";")  // ; instead of ,
          + "\"signature\":\"MEQCIDxBoUCoFRGReLdZ/cABlSSRIKoOEFoU3e27c14vMZtfAiBtX3pGMEpnw6mSAbnagC"
          + "CgHlCk3NcFwWYEyxIE6KGZVA\\u003d\\u003d\"}";

    assertEquals(PLAINTEXT, recipient.unseal(ciphertextEcV1WithNonStrictJsonEncoding));
  }

  @Test
  public void testShouldDecryptECV1WhenUsingCustomKem() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientKem(
                new MyPaymentMethodTokenRecipientKem(MERCHANT_PRIVATE_KEY_PKCS8_BASE64))
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(CIPHERTEXT_EC_V1));
  }

  @Test
  public void testShouldDecryptECV1WhenFetchingSenderVerifyingKeys() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .fetchSenderVerifyingKeysWith(
                new GooglePaymentsPublicKeysManager.Builder()
                    .setHttpTransport(
                        new MockHttpTransport.Builder()
                            .setLowLevelHttpResponse(
                                new MockLowLevelHttpResponse()
                                    .setContent(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON))
                            .build())
                    .build())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(CIPHERTEXT_EC_V1));
  }

  @Test
  public void testShouldTryAllKeysToDecryptECV1() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(ALTERNATE_MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(CIPHERTEXT_EC_V1));
  }

  @Test
  public void testShouldTryAllCustomKemsToDecryptECV1() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientKem(
                new MyPaymentMethodTokenRecipientKem(ALTERNATE_MERCHANT_PRIVATE_KEY_PKCS8_BASE64))
            .addRecipientKem(
                new MyPaymentMethodTokenRecipientKem(MERCHANT_PRIVATE_KEY_PKCS8_BASE64))
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(CIPHERTEXT_EC_V1));
  }

  @Test
  public void testShouldFailIfDecryptingWithDifferentKeyECV1() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(ALTERNATE_MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    try {
      recipient.unseal(CIPHERTEXT_EC_V1);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot decrypt", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfDecryptingWithDifferentCustomKemECV1() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientKem(
                new MyPaymentMethodTokenRecipientKem(ALTERNATE_MERCHANT_PRIVATE_KEY_PKCS8_BASE64))
            .build();

    try {
      recipient.unseal(CIPHERTEXT_EC_V1);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot decrypt", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfVerifyingWithDifferentKeyECV1() throws Exception {
    JsonObject trustedKeysJson =
        JsonParser.parseString(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON).getAsJsonObject();
    trustedKeysJson
        .get("keys")
        .getAsJsonArray()
        .get(INDEX_OF_GOOGLE_SIGNING_EC_V1)
        .getAsJsonObject()
        .addProperty("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY);

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    try {
      recipient.unseal(CIPHERTEXT_EC_V1);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldTryAllKeysToVerifySignatureECV1() throws Exception {
    JsonObject trustedKeysJson =
        JsonParser.parseString(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON).getAsJsonObject();
    JsonArray keys = trustedKeysJson.get("keys").getAsJsonArray();
    JsonObject correctKey = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V1).getAsJsonObject();
    JsonObject wrongKey = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V1).getAsJsonObject().deepCopy();
    wrongKey.addProperty("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY);
    JsonArray newKeys = new JsonArray();
    newKeys.add(wrongKey);
    newKeys.add(correctKey);
    trustedKeysJson.add("keys", newKeys);

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(CIPHERTEXT_EC_V1));
  }

  @Test
  public void testShouldFailIfSignedECV1WithKeyForWrongProtocolVersion() throws Exception {
    JsonObject trustedKeysJson =
        JsonParser.parseString(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON).getAsJsonObject();
    JsonArray keys = trustedKeysJson.get("keys").getAsJsonArray();
    JsonObject correctKeyButWrongProtocol =
        keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V1).getAsJsonObject();
    correctKeyButWrongProtocol.addProperty(
        PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, "ECv2");
    JsonObject wrongKeyButRightProtocol = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V1).getAsJsonObject();
    wrongKeyButRightProtocol.addProperty("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY);
    wrongKeyButRightProtocol.addProperty(
        PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY,
        PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1);
    JsonArray newKeys = new JsonArray();
    newKeys.add(correctKeyButWrongProtocol);
    newKeys.add(wrongKeyButRightProtocol);
    trustedKeysJson.add("keys", newKeys);

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    try {
      recipient.unseal(CIPHERTEXT_EC_V1);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfNoSigningKeysForProtocolVersion() throws Exception {
    JsonObject trustedKeysJson =
        JsonParser.parseString(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON).getAsJsonObject();
    JsonArray keys = trustedKeysJson.get("keys").getAsJsonArray();
    JsonObject key1 = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V1).getAsJsonObject();
    key1.addProperty(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, "ECv2");
    JsonObject key2 = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V1).getAsJsonObject();

    key2.addProperty("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY);
    key2.addProperty(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, "ECv3");
    JsonArray newKeys = new JsonArray();
    newKeys.add(key1);
    newKeys.add(key2);
    trustedKeysJson.add("keys", newKeys);

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    try {
      recipient.unseal(CIPHERTEXT_EC_V1);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("no trusted keys are available for this protocol version", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfSignedMessageWasChangedInECV1() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();
    JsonObject payload = JsonParser.parseString(CIPHERTEXT_EC_V1).getAsJsonObject();
    payload.addProperty(
        PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY,
        payload.get(PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY).getAsString() + " ");
    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfWrongRecipientInECV1() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId("not " + RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();
    try {
      recipient.unseal(CIPHERTEXT_EC_V1);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfECV1SetsWrongProtocolVersion() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();
    JsonObject payload = JsonParser.parseString(CIPHERTEXT_EC_V1).getAsJsonObject();
    String invalidVersion = "ECv2";
    payload.addProperty(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, invalidVersion);
    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("invalid version: " + invalidVersion, e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfProtocolSetToAnInt() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();
    JsonObject payload = JsonParser.parseString(CIPHERTEXT_EC_V1).getAsJsonObject();
    payload.addProperty(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, 1);
    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void testShouldFailIfProtocolSetToAnFloat() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();
    JsonObject payload = JsonParser.parseString(CIPHERTEXT_EC_V1).getAsJsonObject();
    payload.addProperty(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, 1.1);
    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void testShouldSucceedIfMessageIsNotExpired() throws Exception {
    PaymentMethodTokenSender sender =
        new PaymentMethodTokenSender.Builder()
            .senderSigningKey(GOOGLE_SIGNING_EC_V1_PRIVATE_KEY_PKCS8_BASE64)
            .recipientId(RECIPIENT_ID)
            .rawUncompressedRecipientPublicKey(MERCHANT_PUBLIC_KEY_BASE64)
            .build();
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    JsonObject plaintext = new JsonObject();
    plaintext.addProperty(
        "messageExpiration",
        // One day in the future
        String.valueOf(Instant.now().plus(Duration.standardDays(1)).getMillis()));
    plaintext.addProperty("someKey", "someValue");
    String ciphertext = sender.seal(plaintext.toString());
    JsonObject decrypted = JsonParser.parseString(recipient.unseal(ciphertext)).getAsJsonObject();

    assertEquals("someValue", decrypted.get("someKey").getAsString());
  }

  @Test
  public void testShouldFailIfMessageIsExpired() throws Exception {
    PaymentMethodTokenSender sender =
        new PaymentMethodTokenSender.Builder()
            .senderSigningKey(GOOGLE_SIGNING_EC_V1_PRIVATE_KEY_PKCS8_BASE64)
            .recipientId(RECIPIENT_ID)
            .rawUncompressedRecipientPublicKey(MERCHANT_PUBLIC_KEY_BASE64)
            .build();
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    JsonObject expired = new JsonObject();
    expired.addProperty(
        "messageExpiration",
        // One day in the past
        String.valueOf(Instant.now().minus(Duration.standardDays(1)).getMillis()));

    String ciphertext = sender.seal(expired.toString());
    try {
      recipient.unseal(ciphertext);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("expired payload", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfTrustedKeyIsExpiredInECV1() throws Exception {
    JsonObject trustedKeysJson =
        JsonParser.parseString(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON).getAsJsonObject();
    JsonArray keys = trustedKeysJson.get("keys").getAsJsonArray();
    JsonObject key1 = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V1).getAsJsonObject();
    key1.addProperty(
        "keyExpiration", // One day in the past
        String.valueOf(Instant.now().minus(Duration.standardDays(1)).getMillis()));
    JsonArray newKeys = new JsonArray();
    newKeys.add(key1);
    trustedKeysJson.add("keys", newKeys);

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    try {
      recipient.unseal(CIPHERTEXT_EC_V1);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("no trusted keys are available for this protocol version", e.getMessage());
    }
  }

  @Test
  public void testShouldSucceedIfKeyExpirationIsMissingInTrustedKeyIsExpiredForECV1()
      throws Exception {
    JsonObject trustedKeysJson =
        JsonParser.parseString(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON).getAsJsonObject();
    JsonArray keys = trustedKeysJson.get("keys").getAsJsonArray();
    JsonObject key1 = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V1).getAsJsonObject();
    key1.remove("keyExpiration");
    JsonArray newKeys = new JsonArray();
    newKeys.add(key1);
    trustedKeysJson.add("keys", newKeys);

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(CIPHERTEXT_EC_V1));
  }

  @Test
  public void testUnsealECV2() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(sealECV2(PLAINTEXT)));
  }

  @Test
  public void testUnsealECV2WithCustomKem() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientKem(
                new MyPaymentMethodTokenRecipientKem(MERCHANT_PRIVATE_KEY_PKCS8_BASE64))
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(sealECV2(PLAINTEXT)));
  }

  @Test
  public void testShouldFailIfSignedMessageWasChangedInECV2() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();
    JsonObject payload = JsonParser.parseString(sealECV2(PLAINTEXT)).getAsJsonObject();
    payload.addProperty(
        PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY,
        payload.get(PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY).getAsString() + " ");
    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldThrowIfECV2UseWrongSenderId() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .senderId("not-" + PaymentMethodTokenConstants.GOOGLE_SENDER_ID)
            .build();

    try {
      recipient.unseal(sealECV2(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfVerifyingWithDifferentKeyECV2() throws Exception {
    JsonObject trustedKeysJson =
        JsonParser.parseString(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON).getAsJsonObject();
    JsonArray keys = trustedKeysJson.get("keys").getAsJsonArray();
    JsonObject key1 = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V2).getAsJsonObject();
    key1.addProperty("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY);
    JsonArray newKeys = new JsonArray();
    newKeys.add(key1);
    trustedKeysJson.add("keys", newKeys);

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    try {
      recipient.unseal(sealECV2(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfTrustedKeyIsExpiredInECV2() throws Exception {
    JsonObject trustedKeysJson =
        JsonParser.parseString(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON).getAsJsonObject();
    JsonArray keys = trustedKeysJson.get("keys").getAsJsonArray();
    JsonObject key1 = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V2).getAsJsonObject();
    key1.addProperty(
        "keyExpiration", // One day in the past
        String.valueOf(Instant.now().minus(Duration.standardDays(1)).getMillis()));
    JsonArray newKeys = new JsonArray();
    newKeys.add(key1);
    trustedKeysJson.add("keys", newKeys);

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    try {
      recipient.unseal(sealECV2(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("no trusted keys are available for this protocol version", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfKeyExpirationIsMissingInTrustedKeyECV2() throws Exception {
    // Key expiration is required for V2
    JsonObject trustedKeysJson =
        JsonParser.parseString(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON).getAsJsonObject();
    JsonArray keys = trustedKeysJson.get("keys").getAsJsonArray();
    JsonObject key1 = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V2).getAsJsonObject();
    key1.remove("keyExpiration");
    JsonArray newKeys = new JsonArray();
    newKeys.add(key1);
    trustedKeysJson.add("keys", newKeys);

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    try {
      recipient.unseal(sealECV2(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("no trusted keys are available for this protocol version", e.getMessage());
    }
  }

  @Test
  public void testShouldTryAllKeysToVerifySignatureECV2() throws Exception {
    JsonObject trustedKeysJson =
        JsonParser.parseString(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON).getAsJsonObject();
    JsonArray keys = trustedKeysJson.get("keys").getAsJsonArray();
    JsonObject correctKey = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V2).getAsJsonObject();
    JsonObject wrongKey = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V2).getAsJsonObject().deepCopy();
    wrongKey.addProperty("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY);
    JsonArray newKeys = new JsonArray();
    newKeys.add(wrongKey);
    newKeys.add(correctKey);
    trustedKeysJson.add("keys", newKeys);

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(sealECV2(PLAINTEXT)));
  }

  @Test
  public void testShouldFailIfSignedKeyWasChangedInECV2() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    JsonObject payload = JsonParser.parseString(sealECV2(PLAINTEXT)).getAsJsonObject();
    JsonObject intermediateSigningKey = payload.get("intermediateSigningKey").getAsJsonObject();
    intermediateSigningKey.addProperty(
        "signedKey", intermediateSigningKey.get("signedKey").getAsString() + " ");
    payload.add("intermediateSigningKey", intermediateSigningKey);
    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldThrowIfSignatureForSignedKeyIsIncorrectInECV2() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();
    JsonObject payload = JsonParser.parseString(sealECV2(PLAINTEXT)).getAsJsonObject();
    JsonObject intermediateSigningKey = payload.get("intermediateSigningKey").getAsJsonObject();
    JsonArray signatures = intermediateSigningKey.get("signatures").getAsJsonArray();
    String correctSignature = signatures.get(0).getAsString();
    byte[] wrongSignatureBytes = Base64.decode(correctSignature);
    wrongSignatureBytes[0] = (byte) ~wrongSignatureBytes[0];
    JsonArray newSignatures = new JsonArray();
    newSignatures.add(Base64.encode(wrongSignatureBytes));
    intermediateSigningKey.add("signatures", newSignatures);
    payload.add("intermediateSigningKey", intermediateSigningKey);

    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldTryVerifyingAllSignaturesForSignedKeyInECV2() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();
    JsonObject payload = JsonParser.parseString(sealECV2(PLAINTEXT)).getAsJsonObject();
    JsonObject intermediateSigningKey = payload.get("intermediateSigningKey").getAsJsonObject();
    JsonArray signatures = intermediateSigningKey.get("signatures").getAsJsonArray();
    String correctSignature = signatures.get(0).getAsString();
    byte[] wrongSignatureBytes = Base64.decode(correctSignature);
    wrongSignatureBytes[0] = (byte) ~wrongSignatureBytes[0];
    JsonArray newSignatures = new JsonArray();
    newSignatures.add(Base64.encode(wrongSignatureBytes));
    newSignatures.add(correctSignature);
    intermediateSigningKey.add("signatures", newSignatures);
    payload.add("intermediateSigningKey", intermediateSigningKey);

    assertEquals(PLAINTEXT, recipient.unseal(sealECV2(PLAINTEXT)));
  }

  @Test
  public void testShouldThrowIfECV2UseWrongRecipientId() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId("not" + RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    try {
      recipient.unseal(sealECV2(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldAcceptNonExpiredECV2Message() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    JsonObject payload = new JsonObject();
    payload.addProperty(
        "messageExpiration",
        // One day in the future
        String.valueOf(Instant.now().plus(Duration.standardDays(1)).getMillis()));
    String plaintext = payload.toString();
    assertEquals(plaintext, recipient.unseal(sealECV2(plaintext)));
  }

  @Test
  public void testShouldFailIfECV2MessageIsExpired() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    JsonObject payload = new JsonObject();
    payload.addProperty(
        "messageExpiration",
        // One day in the past
        String.valueOf(Instant.now().minus(Duration.standardDays(1)).getMillis()));

    String ciphertext = sealECV2(payload.toString());
    try {
      recipient.unseal(ciphertext);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("expired payload", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfIntermediateSigningKeyIsExpiredInECV2() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();
    PaymentMethodTokenSender sender =
        new PaymentMethodTokenSender.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderIntermediateSigningKey(
                GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PRIVATE_KEY_PKCS8_BASE64)
            .senderIntermediateCert(
                new SenderIntermediateCertFactory.Builder()
                    .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
                    .addSenderSigningKey(GOOGLE_SIGNING_EC_V2_PRIVATE_KEY_PKCS8_BASE64)
                    .senderIntermediateSigningKey(
                        GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PUBLIC_KEY_X509_BASE64)
                    // Expiration date in the past.
                    .expiration(Instant.now().minus(Duration.standardDays(1)).getMillis())
                    .build()
                    .create())
            .recipientId(RECIPIENT_ID)
            .rawUncompressedRecipientPublicKey(MERCHANT_PUBLIC_KEY_BASE64)
            .build();

    try {
      recipient.unseal(sender.seal(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("expired intermediateSigningKey", e.getMessage());
    }
  }

  private static String sealECV2(String plaintext) throws GeneralSecurityException {
    return new PaymentMethodTokenSender.Builder()
        .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
        .senderIntermediateSigningKey(GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PRIVATE_KEY_PKCS8_BASE64)
        .senderIntermediateCert(
            new SenderIntermediateCertFactory.Builder()
                .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
                .addSenderSigningKey(GOOGLE_SIGNING_EC_V2_PRIVATE_KEY_PKCS8_BASE64)
                .senderIntermediateSigningKey(
                    GOOGLE_SIGNING_EC_V2_INTERMEDIATE_PUBLIC_KEY_X509_BASE64)
                .expiration(Instant.now().plus(Duration.standardDays(1)).getMillis())
                .build()
                .create())
        .recipientId(RECIPIENT_ID)
        .rawUncompressedRecipientPublicKey(MERCHANT_PUBLIC_KEY_BASE64)
        .build()
        .seal(plaintext);
  }

  @Test
  public void testVerifyECV2SigningOnly() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(signECV2SigningOnly(PLAINTEXT)));
  }

  @Test
  public void testShouldFailIfSignedMessageWasChangedInECV2SigningOnly() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .build();
    JsonObject payload = JsonParser.parseString(signECV2SigningOnly(PLAINTEXT)).getAsJsonObject();
    payload.addProperty(
        PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY,
        payload.get(PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY).getAsString() + " ");
    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldThrowIfECV2SigningOnlyUseWrongSenderId() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .senderId("not-" + PaymentMethodTokenConstants.GOOGLE_SENDER_ID)
            .build();

    try {
      recipient.unseal(signECV2SigningOnly(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfVerifyingWithDifferentKeyECV2SigningOnly() throws Exception {
    JsonObject trustedKeysJson =
        JsonParser.parseString(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON).getAsJsonObject();
    JsonArray keys = trustedKeysJson.get("keys").getAsJsonArray();
    JsonObject key = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V2_SIGNING_ONLY).getAsJsonObject();
    key.addProperty("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY);
    JsonArray newKeys = new JsonArray();
    newKeys.add(key);
    trustedKeysJson.add("keys", newKeys);

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .build();

    try {
      recipient.unseal(signECV2SigningOnly(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfTrustedKeyIsExpiredInECV2SigningOnly() throws Exception {
    JsonObject trustedKeysJson =
        JsonParser.parseString(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON).getAsJsonObject();
    JsonArray keys = trustedKeysJson.get("keys").getAsJsonArray();
    JsonObject key = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V2_SIGNING_ONLY).getAsJsonObject();
    key.addProperty(
        "keyExpiration", // One day in the past
        String.valueOf(Instant.now().minus(Duration.standardDays(1)).getMillis()));
    JsonArray newKeys = new JsonArray();
    newKeys.add(key);
    trustedKeysJson.add("keys", newKeys);

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .build();

    try {
      recipient.unseal(signECV2SigningOnly(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("no trusted keys are available for this protocol version", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfKeyExpirationIsMissingInTrustedKeyECV2SigningOnly() throws Exception {
    // Key expiration is required for ECv2SigningOnly
    JsonObject trustedKeysJson =
        JsonParser.parseString(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON).getAsJsonObject();
    JsonArray keys = trustedKeysJson.get("keys").getAsJsonArray();
    JsonObject key = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V2_SIGNING_ONLY).getAsJsonObject();
    key.remove("keyExpiration");
    JsonArray newKeys = new JsonArray();
    newKeys.add(key);
    trustedKeysJson.add("keys", newKeys);

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .build();

    try {
      recipient.unseal(signECV2SigningOnly(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("no trusted keys are available for this protocol version", e.getMessage());
    }
  }

  @Test
  public void testShouldTryAllKeysToVerifySignatureECV2SigningOnly() throws Exception {
    JsonObject trustedKeysJson =
        JsonParser.parseString(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON).getAsJsonObject();
    JsonArray keys = trustedKeysJson.get("keys").getAsJsonArray();
    JsonObject correctKey = keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V2_SIGNING_ONLY).getAsJsonObject();
    JsonObject wrongKey =
        keys.get(INDEX_OF_GOOGLE_SIGNING_EC_V2_SIGNING_ONLY).getAsJsonObject().deepCopy();
    wrongKey.addProperty("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY);
    JsonArray newKeys = new JsonArray();
    newKeys.add(wrongKey);
    newKeys.add(correctKey);
    trustedKeysJson.add("keys", newKeys);

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(signECV2SigningOnly(PLAINTEXT)));
  }

  @Test
  public void testShouldFailIfSignedKeyWasChangedInECV2SigningOnly() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .build();

    JsonObject payload = JsonParser.parseString(signECV2SigningOnly(PLAINTEXT)).getAsJsonObject();
    JsonObject intermediateSigningKey = payload.get("intermediateSigningKey").getAsJsonObject();
    intermediateSigningKey.addProperty(
        "signedKey", intermediateSigningKey.get("signedKey").getAsString() + " ");
    payload.add("intermediateSigningKey", intermediateSigningKey);

    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldThrowIfSignatureForSignedKeyIsIncorrectInECV2SigningOnly()
      throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .build();
    JsonObject payload = JsonParser.parseString(signECV2SigningOnly(PLAINTEXT)).getAsJsonObject();
    JsonArray signatures =
        payload.get("intermediateSigningKey").getAsJsonObject().get("signatures").getAsJsonArray();
    String correctSignature = signatures.get(0).getAsString();
    byte[] wrongSignatureBytes = Base64.decode(correctSignature);
    wrongSignatureBytes[0] = (byte) ~wrongSignatureBytes[0];
    JsonArray newSignatures = new JsonArray();
    newSignatures.add(Base64.encode(wrongSignatureBytes));
    JsonObject intermediateSigningKey = payload.get("intermediateSigningKey").getAsJsonObject();
    intermediateSigningKey.add("signatures", newSignatures);
    payload.add("intermediateSigningKey", intermediateSigningKey);

    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldTryVerifyingAllSignaturesForSignedKeyInECV2SigningOnly() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .build();
    JsonObject payload = JsonParser.parseString(signECV2SigningOnly(PLAINTEXT)).getAsJsonObject();
    JsonArray signatures =
        payload.get("intermediateSigningKey").getAsJsonObject().get("signatures").getAsJsonArray();
    String correctSignature = signatures.get(0).getAsString();
    byte[] wrongSignatureBytes = Base64.decode(correctSignature);
    wrongSignatureBytes[0] = (byte) ~wrongSignatureBytes[0];
    JsonArray newSignatures = new JsonArray();
    newSignatures.add(Base64.encode(wrongSignatureBytes));
    newSignatures.add(correctSignature);
    JsonObject intermediateSigningKey = payload.get("intermediateSigningKey").getAsJsonObject();
    intermediateSigningKey.add("signatures", newSignatures);
    payload.add("intermediateSigningKey", intermediateSigningKey);

    assertEquals(PLAINTEXT, recipient.unseal(signECV2SigningOnly(PLAINTEXT)));
  }

  @Test
  public void testShouldThrowIfECV2SigningOnlyUseWrongRecipientId() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId("not" + RECIPIENT_ID)
            .build();

    try {
      recipient.unseal(signECV2SigningOnly(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldAcceptNonExpiredECV2SigningOnlyMessage() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .build();

    JsonObject payload = new JsonObject();
    payload.addProperty(
        "messageExpiration",
        // One day in the future
        String.valueOf(Instant.now().plus(Duration.standardDays(1)).getMillis()));
    String plaintext = payload.toString();
    assertEquals(plaintext, recipient.unseal(signECV2SigningOnly(plaintext)));
  }

  @Test
  public void testShouldFailIfECV2SigningOnlyMessageIsExpired() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .build();

    JsonObject payload = new JsonObject();
    payload.addProperty(
        "messageExpiration",
        // One day in the past
        String.valueOf(Instant.now().minus(Duration.standardDays(1)).getMillis()));
    String ciphertext = signECV2SigningOnly(payload.toString());
    try {
      recipient.unseal(ciphertext);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("expired payload", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfIntermediateSigningKeyIsExpiredInECV2SigningOnly() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .build();
    PaymentMethodTokenSender sender =
        new PaymentMethodTokenSender.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
            .senderIntermediateSigningKey(
                GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_INTERMEDIATE_PRIVATE_KEY_PKCS8_BASE64)
            .senderIntermediateCert(
                new SenderIntermediateCertFactory.Builder()
                    .protocolVersion(
                        PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
                    .addSenderSigningKey(GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_PRIVATE_KEY_PKCS8_BASE64)
                    .senderIntermediateSigningKey(
                        GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_INTERMEDIATE_PUBLIC_KEY_X509_BASE64)
                    // Expiration date in the past.
                    .expiration(Instant.now().minus(Duration.standardDays(1)).getMillis())
                    .build()
                    .create())
            .recipientId(RECIPIENT_ID)
            .build();

    try {
      recipient.unseal(sender.seal(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("expired intermediateSigningKey", e.getMessage());
    }
  }

  private static String signECV2SigningOnly(String plaintext) throws GeneralSecurityException {
    return new PaymentMethodTokenSender.Builder()
        .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
        .senderIntermediateSigningKey(
            GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_INTERMEDIATE_PRIVATE_KEY_PKCS8_BASE64)
        .senderIntermediateCert(
            new SenderIntermediateCertFactory.Builder()
                .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)
                .addSenderSigningKey(GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_PRIVATE_KEY_PKCS8_BASE64)
                .senderIntermediateSigningKey(
                    GOOGLE_SIGNING_EC_V2_SIGNING_ONLY_INTERMEDIATE_PUBLIC_KEY_X509_BASE64)
                .expiration(Instant.now().plus(Duration.standardDays(1)).getMillis())
                .build()
                .create())
        .recipientId(RECIPIENT_ID)
        .build()
        .seal(plaintext);
  }
}
