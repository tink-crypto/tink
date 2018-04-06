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
import java.security.GeneralSecurityException;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.json.JSONArray;
import org.json.JSONObject;
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
          + "  ],\n"
          + "}";

  /** Index within {@link #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON} of the ECv1 Google signing key. */
  private static final int INDEX_OF_GOOGLE_SIGNING_EC_V1 = 0;

  /** Index within {@link #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON} of the ECv1 Google signing key. */
  private static final int INDEX_OF_GOOGLE_SIGNING_EC_V2 = 1;

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

  @Test
  public void testShouldDecryptV1() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(CIPHERTEXT_EC_V1));
  }

  @Test
  public void testShouldDecryptV1WhenFetchingSenderVerifyingKeys() throws Exception {
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
  public void testShouldTryAllKeysToDecryptV1() throws Exception {
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
  public void testShouldFailIfDecryptingWithDifferentKeyV1() throws Exception {
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
  public void testShouldFailIfVerifyingWithDifferentKeyV1() throws Exception {
    JSONObject trustedKeysJson = new JSONObject(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON);
    trustedKeysJson
        .getJSONArray("keys")
        .getJSONObject(INDEX_OF_GOOGLE_SIGNING_EC_V1)
        .put("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY);

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
  public void testShouldTryAllKeysToVerifySignatureV1() throws Exception {
    JSONObject trustedKeysJson = new JSONObject(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON);
    JSONArray keys = trustedKeysJson.getJSONArray("keys");
    JSONObject correctKey =
        new JSONObject(keys.getJSONObject(INDEX_OF_GOOGLE_SIGNING_EC_V1).toString());
    JSONObject wrongKey =
        new JSONObject(keys.getJSONObject(INDEX_OF_GOOGLE_SIGNING_EC_V1).toString())
            .put("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY);
    trustedKeysJson.put("keys", new JSONArray().put(wrongKey).put(correctKey));

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(CIPHERTEXT_EC_V1));
  }

  @Test
  public void testShouldFailIfSignedV1WithKeyForWrongProtocolVersion() throws Exception {
    JSONObject trustedKeysJson = new JSONObject(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON);
    JSONArray keys = trustedKeysJson.getJSONArray("keys");
    JSONObject correctKeyButWrongProtocol =
        new JSONObject(keys.getJSONObject(INDEX_OF_GOOGLE_SIGNING_EC_V1).toString())
            .put(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, "ECv2");
    JSONObject wrongKeyButRightProtocol =
        new JSONObject(keys.getJSONObject(INDEX_OF_GOOGLE_SIGNING_EC_V1).toString())
            .put("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY)
            .put(
                PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY,
                PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1);
    trustedKeysJson.put(
        "keys", new JSONArray().put(correctKeyButWrongProtocol).put(wrongKeyButRightProtocol));

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
    JSONObject trustedKeysJson = new JSONObject(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON);
    JSONArray keys = trustedKeysJson.getJSONArray("keys");
    JSONObject key1 =
        new JSONObject(keys.getJSONObject(INDEX_OF_GOOGLE_SIGNING_EC_V1).toString())
            .put(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, "ECv2");
    JSONObject key2 =
        new JSONObject(keys.getJSONObject(INDEX_OF_GOOGLE_SIGNING_EC_V1).toString())
            .put("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY)
            .put(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, "ECv3");
    trustedKeysJson.put("keys", new JSONArray().put(key1).put(key2));

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
  public void testShouldFailIfSignedMessageWasChangedInV1() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();
    JSONObject payload = new JSONObject(CIPHERTEXT_EC_V1);
    payload.put(
        PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY,
        payload.getString(PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY) + " ");
    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfWrongRecipientInV1() throws Exception {
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
  public void testShouldFailIfV1SetsWrongProtocolVersion() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();
    JSONObject payload = new JSONObject(CIPHERTEXT_EC_V1);
    String invalidVersion = "ECv2";
    payload.put(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, invalidVersion);
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
    JSONObject payload = new JSONObject(CIPHERTEXT_EC_V1);
    payload.put(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, 1);
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
    JSONObject payload = new JSONObject(CIPHERTEXT_EC_V1);
    payload.put(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, 1.1);
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

    String ciphertext =
        sender.seal(
            new JSONObject()
                .put(
                    "messageExpiration",
                    // One day in the future
                    String.valueOf(Instant.now().plus(Duration.standardDays(1)).getMillis()))
                .put("someKey", "someValue")
                .toString());
    assertEquals("someValue", new JSONObject(recipient.unseal(ciphertext)).getString("someKey"));
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

    String ciphertext =
        sender.seal(
            new JSONObject()
                .put(
                    "messageExpiration",
                    // One day in the past
                    String.valueOf(Instant.now().minus(Duration.standardDays(1)).getMillis()))
                .toString());
    try {
      recipient.unseal(ciphertext);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("expired payload", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfTrustedKeyIsExpiredInV1() throws Exception {
    JSONObject trustedKeysJson = new JSONObject(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON);
    trustedKeysJson
        .getJSONArray("keys")
        .getJSONObject(INDEX_OF_GOOGLE_SIGNING_EC_V1)
        .put(
            "keyExpiration",
            // One day in the past
            String.valueOf(Instant.now().minus(Duration.standardDays(1)).getMillis()));

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
  public void testShouldSucceedIfKeyExpirationIsMissingInTrustedKeyIsExpiredForV1()
      throws Exception {
    JSONObject trustedKeysJson = new JSONObject(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON);
    trustedKeysJson
        .getJSONArray("keys")
        .getJSONObject(INDEX_OF_GOOGLE_SIGNING_EC_V1)
        .remove("keyExpiration");

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(CIPHERTEXT_EC_V1));
  }

  @Test
  public void testUnsealV2() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(sealV2(PLAINTEXT)));
  }

  @Test
  public void testShouldFailIfSignedMessageWasChangedInV2() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();
    JSONObject payload = new JSONObject(sealV2(PLAINTEXT));
    payload.put(
        PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY,
        payload.getString(PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY) + " ");
    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testThrowIfV2UseWrongSenderId() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .senderId("not-" + PaymentMethodTokenConstants.GOOGLE_SENDER_ID)
            .build();

    try {
      recipient.unseal(sealV2(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfVerifyingWithDifferentKeyV2() throws Exception {
    JSONObject trustedKeysJson = new JSONObject(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON);
    trustedKeysJson
        .getJSONArray("keys")
        .getJSONObject(INDEX_OF_GOOGLE_SIGNING_EC_V2)
        .put("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY);

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    try {
      recipient.unseal(sealV2(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfTrustedKeyIsExpiredInV2() throws Exception {
    JSONObject trustedKeysJson = new JSONObject(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON);
    trustedKeysJson
        .getJSONArray("keys")
        .getJSONObject(INDEX_OF_GOOGLE_SIGNING_EC_V2)
        .put(
            "keyExpiration",
            // One day in the past
            String.valueOf(Instant.now().minus(Duration.standardDays(1)).getMillis()));

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    try {
      recipient.unseal(sealV2(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("no trusted keys are available for this protocol version", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfKeyExpirationIsMissingInTrustedKeyIsExpiredForV2() throws Exception {
    // Key expiration is required for V2
    JSONObject trustedKeysJson = new JSONObject(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON);
    trustedKeysJson
        .getJSONArray("keys")
        .getJSONObject(INDEX_OF_GOOGLE_SIGNING_EC_V2)
        .remove("keyExpiration");

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    try {
      recipient.unseal(sealV2(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("no trusted keys are available for this protocol version", e.getMessage());
    }
  }

  @Test
  public void testShouldTryAllKeysToVerifySignatureV2() throws Exception {
    JSONObject trustedKeysJson = new JSONObject(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON);
    JSONArray keys = trustedKeysJson.getJSONArray("keys");
    JSONObject correctKey =
        new JSONObject(keys.getJSONObject(INDEX_OF_GOOGLE_SIGNING_EC_V2).toString());
    JSONObject wrongKey =
        new JSONObject(keys.getJSONObject(INDEX_OF_GOOGLE_SIGNING_EC_V2).toString())
            .put("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY);
    trustedKeysJson.put("keys", new JSONArray().put(wrongKey).put(correctKey));

    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(trustedKeysJson.toString())
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    assertEquals(PLAINTEXT, recipient.unseal(sealV2(PLAINTEXT)));
  }

  @Test
  public void testShouldFailIfSignedKeyWasChangedInV2() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    JSONObject payload = new JSONObject(sealV2(PLAINTEXT));
    payload
        .getJSONObject("intermediateSigningKey")
        .put(
            "signedKey",
            payload.getJSONObject("intermediateSigningKey").getString("signedKey") + " ");
    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldThrowIfSignatureForSignedKeyIsIncorrectInV2() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();
    JSONObject payload = new JSONObject(sealV2(PLAINTEXT));
    JSONArray signatures =
        payload.getJSONObject("intermediateSigningKey").getJSONArray("signatures");
    String correctSignature = signatures.getString(0);
    byte[] wrongSignatureBytes = Base64.decode(correctSignature);
    wrongSignatureBytes[0] = (byte) ~wrongSignatureBytes[0];
    payload
        .getJSONObject("intermediateSigningKey")
        .put("signatures", new JSONArray().put(Base64.encode(wrongSignatureBytes)));

    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldTryVerifyingAllSignaturesForSignedKeyInV2() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();
    JSONObject payload = new JSONObject(sealV2(PLAINTEXT));
    JSONArray signatures =
        payload.getJSONObject("intermediateSigningKey").getJSONArray("signatures");
    String correctSignature = signatures.getString(0);
    byte[] wrongSignatureBytes = Base64.decode(correctSignature);
    wrongSignatureBytes[0] = (byte) ~wrongSignatureBytes[0];
    payload
        .getJSONObject("intermediateSigningKey")
        .put(
            "signatures",
            new JSONArray().put(Base64.encode(wrongSignatureBytes)).put(correctSignature));

    assertEquals(PLAINTEXT, recipient.unseal(sealV2(PLAINTEXT)));
  }

  @Test
  public void testThrowIfV2UseWrongRecipientId() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId("not" + RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    try {
      recipient.unseal(sealV2(PLAINTEXT));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldAcceptNonExpiredV2Message() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    String plaintext =
        new JSONObject()
            .put(
                "messageExpiration",
                // One day in the future
                String.valueOf(Instant.now().plus(Duration.standardDays(1)).getMillis()))
            .toString();
    assertEquals(plaintext, recipient.unseal(sealV2(plaintext)));
  }

  @Test
  public void testShouldFailIfV2MessageIsExpired() throws Exception {
    PaymentMethodTokenRecipient recipient =
        new PaymentMethodTokenRecipient.Builder()
            .protocolVersion(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
            .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .recipientId(RECIPIENT_ID)
            .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
            .build();

    String ciphertext =
        sealV2(
            new JSONObject()
                .put(
                    "messageExpiration",
                    // One day in the past
                    String.valueOf(Instant.now().minus(Duration.standardDays(1)).getMillis()))
                .toString());
    try {
      recipient.unseal(ciphertext);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("expired payload", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfIntermediateSigningKeyIsExpiredInV2() throws Exception {
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

  private static String sealV2(String plaintext) throws GeneralSecurityException {
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
}
