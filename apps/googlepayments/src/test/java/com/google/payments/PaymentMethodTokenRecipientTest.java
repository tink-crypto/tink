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

package com.google.payments;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.security.GeneralSecurityException;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@code PaymentMethodTokenRecipient}.
 */
@RunWith(JUnit4.class)
public class PaymentMethodTokenRecipientTest {
  /**
   * Created with:
   *
   * <pre>
   * openssl pkcs8 -topk8 -inform PEM -outform PEM -in merchant-key.pem -nocrypt
   * </pre>
   */
  private static final String MERCHANT_PRIVATE_KEY_PKCS8_BASE64 =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjj"
          + "chHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx"
          + "9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm";

  private static final String ALTERNATE_MERCHANT_PRIVATE_KEY_PKCS8_BASE64 =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOUIzccyJ3rTx6SVm"
          + "XrWdtwUP0NU26nvc8KIYw2GmYZKhRANCAAR5AjmTNAE93hQEQE+PryLlgr6Q7FXyN"
          + "XoZRk+1Fikhq61mFhQ9s14MOwGBxd5O6Jwn/sdUrWxkYk3idtNEN1Rz";

  /**
   * Public key value created with:
   *
   * <pre>
   * openssl ec -in google-key.pem -inform PEM -outform PEM -pubout
   * </pre>
   */
  private static final String GOOGLE_VERIFYING_PUBLIC_KEYS_JSON =
      "{\n"
          + "  \"keys\": [\n"
          + "    {\n"
          + "      \"keyValue\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPYnHwS8uegWAewQtlxizmLFynw"
          + "HcxRT1PK07cDA6/C4sXrVI1SzZCUx8U8S0LjMrT6ird/VW7be3Mz6t/srtRQ==\",\n"
          + "      \"protocolVersion\": \"ECv1\"\n"
          + "    },\n"
          + "  ],\n"
          + "}";

  private static final String RECIPIENT_ID = "someRecipient";

  private static final String PLAINTEXT = "plaintext";

  /**
   * The result of {@link #PLAINTEXT} encrypted with {@link #MERCHANT_PRIVATE_KEY_PKCS8_BASE64}
   * and signed with the only key in {@link #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON}.
   */
  private static final String CIPHERTEXT =
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
    PaymentMethodTokenRecipient recipient = new PaymentMethodTokenRecipient.Builder()
        .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
        .recipientId(RECIPIENT_ID)
        .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
        .build();

    assertEquals(PLAINTEXT, recipient.unseal(CIPHERTEXT));
  }

  @Test
  public void testShouldTryAllKeysToDecryptV1() throws Exception {
    PaymentMethodTokenRecipient recipient = new PaymentMethodTokenRecipient.Builder()
        .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
        .recipientId(RECIPIENT_ID)
        .addRecipientPrivateKey(ALTERNATE_MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
        .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
        .build();

    assertEquals(PLAINTEXT, recipient.unseal(CIPHERTEXT));
  }

  @Test
  public void testShouldFailIfDecryptingWithDifferentKeyV1() throws Exception {
    PaymentMethodTokenRecipient recipient = new PaymentMethodTokenRecipient.Builder()
        .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
        .recipientId(RECIPIENT_ID)
        .addRecipientPrivateKey(ALTERNATE_MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
        .build();

    try {
      recipient.unseal(CIPHERTEXT);
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
        .getJSONObject(0)
        .put("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY);

    PaymentMethodTokenRecipient recipient = new PaymentMethodTokenRecipient.Builder()
        .senderVerifyingKeys(trustedKeysJson.toString())
        .recipientId(RECIPIENT_ID)
        .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
        .build();

    try {
      recipient.unseal(CIPHERTEXT);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldTryAllKeysToVerifySignatureV1() throws Exception {
    JSONObject trustedKeysJson = new JSONObject(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON);
    JSONArray keys = trustedKeysJson.getJSONArray("keys");
    JSONObject correctKey = new JSONObject(keys.getJSONObject(0).toString());
    JSONObject wrongKey =
        new JSONObject(keys.getJSONObject(0).toString())
            .put("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY);
    trustedKeysJson.put("keys", new JSONArray().put(wrongKey).put(correctKey));

    PaymentMethodTokenRecipient recipient = new PaymentMethodTokenRecipient.Builder()
        .senderVerifyingKeys(trustedKeysJson.toString())
        .recipientId(RECIPIENT_ID)
        .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
        .build();

    assertEquals(PLAINTEXT, recipient.unseal(CIPHERTEXT));
  }

  @Test
  public void testShouldFailIfSignedV1WithKeyForWrongProtocolVersion() throws Exception {
    JSONObject trustedKeysJson = new JSONObject(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON);
    JSONArray keys = trustedKeysJson.getJSONArray("keys");
    JSONObject correctKeyButWrongProtocol = new JSONObject(keys.getJSONObject(0).toString())
        .put(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, "ECv2");
    JSONObject wrongKeyButRightProtocol =
        new JSONObject(keys.getJSONObject(0).toString())
            .put("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY)
            .put(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY,
                PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1);
    trustedKeysJson.put(
        "keys", new JSONArray().put(correctKeyButWrongProtocol).put(wrongKeyButRightProtocol));

    PaymentMethodTokenRecipient recipient = new PaymentMethodTokenRecipient.Builder()
        .senderVerifyingKeys(trustedKeysJson.toString())
        .recipientId(RECIPIENT_ID)
        .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
        .build();

    try {
      recipient.unseal(CIPHERTEXT);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfNoSigningKeysForProtocolVersion() throws Exception {
    JSONObject trustedKeysJson = new JSONObject(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON);
    JSONArray keys = trustedKeysJson.getJSONArray("keys");
    JSONObject key1 = new JSONObject(keys.getJSONObject(0).toString())
        .put(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, "ECv2");
    JSONObject key2 =
        new JSONObject(keys.getJSONObject(0).toString())
            .put("keyValue", ALTERNATE_PUBLIC_SIGNING_KEY)
            .put(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, "ECv3");
    trustedKeysJson.put("keys", new JSONArray().put(key1).put(key2));

    try {
      PaymentMethodTokenRecipient recipient = new PaymentMethodTokenRecipient.Builder()
          .senderVerifyingKeys(trustedKeysJson.toString())
          .recipientId(RECIPIENT_ID)
          .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
          .build();
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertEquals("no trusted keys are available for this protocol version", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfSignedMessageWasChangedInV1() throws Exception {
    PaymentMethodTokenRecipient recipient = new PaymentMethodTokenRecipient.Builder()
        .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
        .recipientId(RECIPIENT_ID)
        .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
        .build();
    JSONObject payload = new JSONObject(CIPHERTEXT);
    payload.put(PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY,
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
    PaymentMethodTokenRecipient recipient = new PaymentMethodTokenRecipient.Builder()
        .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
        .recipientId("not " + RECIPIENT_ID)
        .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
        .build();
    try {
      recipient.unseal(CIPHERTEXT);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot verify signature", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfV1SetsWrongProtocolVersion() throws Exception {
    PaymentMethodTokenRecipient recipient = new PaymentMethodTokenRecipient.Builder()
        .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
        .recipientId(RECIPIENT_ID)
        .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
        .build();
    JSONObject payload = new JSONObject(CIPHERTEXT);
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
    PaymentMethodTokenRecipient recipient = new PaymentMethodTokenRecipient.Builder()
        .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
        .recipientId(RECIPIENT_ID)
        .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
        .build();
    JSONObject payload = new JSONObject(CIPHERTEXT);
    payload.put(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, 1);
    System.out.println(payload);
    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot unseal; invalid JSON message", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfProtocolSetToAnFloat() throws Exception {
    PaymentMethodTokenRecipient recipient = new PaymentMethodTokenRecipient.Builder()
        .senderVerifyingKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
        .recipientId(RECIPIENT_ID)
        .addRecipientPrivateKey(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
        .build();
    JSONObject payload = new JSONObject(CIPHERTEXT);
    payload.put(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, 1.1);
    System.out.println(payload);
    try {
      recipient.unseal(payload.toString());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("cannot unseal; invalid JSON message", e.getMessage());
    }
  }
}
