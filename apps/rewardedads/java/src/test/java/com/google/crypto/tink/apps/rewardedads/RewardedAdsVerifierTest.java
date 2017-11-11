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

package com.google.crypto.tink.apps.rewardedads;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.util.KeysDownloader;
import java.net.URI;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@code RewardedAdsVerifier}. */
@RunWith(JUnit4.class)
public class RewardedAdsVerifierTest {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  /** Sample Google provided JSON with its public signing keys. */
  private static final String GOOGLE_VERIFYING_PUBLIC_KEYS_JSON =
      "{\n"
          + "  \"keys\": [\n"
          + "    {\n"
          + "      \"base64\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPYnHwS8uegWAewQtlxizmLFynw"
          + "HcxRT1PK07cDA6/C4sXrVI1SzZCUx8U8S0LjMrT6ird/VW7be3Mz6t/srtRQ==\",\n"
          + "      \"keyId\": 1234\n"
          + "    },\n"
          + "  ],\n"
          + "}";

  /**
   * Sample Google private signing key.
   *
   * <p>Corresponds to private key of the key in {@link #GOOGLE_VERIFYING_PUBLIC_KEYS_JSON}.
   */
  private static final String GOOGLE_SIGNING_PRIVATE_KEY_PKCS8_BASE64 =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZj/Dldxz8fvKVF5O"
          + "TeAtK6tY3G1McmvhMppe6ayW6GahRANCAAQ9icfBLy56BYB7BC2XGLOYsXKfAdzF"
          + "FPU8rTtwMDr8LixetUjVLNkJTHxTxLQuMytPqKt39Vbtt7czPq3+yu1F";

  // must match the value in GOOGLE_VERIFYING_PUBLIC_KEYS_JSON
  private static final int KEY_ID = 1234;
  private static final String REWARD_HOST_AND_PATH = "https://publisher.com/blah?";
  private static final String REWARD_QUERY = "foo1=bar1&foo2=bar2";
  private static final String REWARD_URL = REWARD_HOST_AND_PATH + REWARD_QUERY;

  private static final String ALTERNATE_PUBLIC_SIGNING_KEY =
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEU8E6JppGKFG40r5dDU1idHRN52NuwsemFzXZh1oUqh3bGUPgPioH+RoW"
          + "nmVSUQz1WfM2426w9f0GADuXzpUkcw==";

  private static String signUrl(String rewardUrl, String privateKey, int keyId) throws Exception {
    EcdsaSignJce signer =
        new EcdsaSignJce(
            EllipticCurves.getEcPrivateKey(Base64.decode(privateKey)), "SHA256WithECDSA");
    String queryString = new URI(rewardUrl).getQuery();
    return buildUrl(rewardUrl, signer.sign(queryString.getBytes(UTF_8)), keyId);
  }

  private static String buildUrl(String rewardUrl, byte[] sig, int keyId) {
    return new StringBuilder(rewardUrl)
        .append("&")
        .append(RewardedAdsVerifier.SIGNATURE_PARAM_NAME)
        .append(Base64.urlSafeEncode(sig))
        .append("&")
        .append(RewardedAdsVerifier.KEY_ID_PARAM_NAME)
        .append(keyId)
        .toString();
  }

  @Test
  public void testShouldVerify() throws Exception {
    RewardedAdsVerifier verifier =
        new RewardedAdsVerifier.Builder()
            .setVerifyingPublicKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .build();
    verifier.verify(signUrl(REWARD_URL, GOOGLE_SIGNING_PRIVATE_KEY_PKCS8_BASE64, KEY_ID));
  }

  @Test
  public void testShouldVerifyWithEncodedUrl() throws Exception {
    RewardedAdsVerifier verifier =
        new RewardedAdsVerifier.Builder()
            .setVerifyingPublicKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .build();

    String rewardUrl = "https://publisher.com/path?foo=hello%20world&bar=user%40gmail.com";
    String decodedQueryString = "foo=hello world&bar=user@gmail.com";
    EcdsaSignJce signer =
        new EcdsaSignJce(
            EllipticCurves.getEcPrivateKey(
                Base64.decode(GOOGLE_SIGNING_PRIVATE_KEY_PKCS8_BASE64)),
            "SHA256WithECDSA");
    byte[] signature = signer.sign(decodedQueryString.getBytes(UTF_8));
    String signedUrl = buildUrl(rewardUrl, signature, KEY_ID);
    verifier.verify(signedUrl);
  }

  @Test
  public void testShouldDecryptV1WhenFetchingSenderVerifyingKeys() throws Exception {
    RewardedAdsVerifier verifier =
        new RewardedAdsVerifier.Builder()
            .fetchVerifyingPublicKeysWith(
                new KeysDownloader.Builder()
                    .setHttpTransport(
                        new MockHttpTransport.Builder()
                            .setLowLevelHttpResponse(
                                new MockLowLevelHttpResponse()
                                    .setContent(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON))
                            .build())
                    .setUrl("https://someUrl" /* unused */)
                    .build())
            .build();

    verifier.verify(signUrl(REWARD_URL, GOOGLE_SIGNING_PRIVATE_KEY_PKCS8_BASE64, KEY_ID));
  }

  @Test
  public void testShouldFailIfVerifyingWithDifferentKey() throws Exception {
    JSONObject trustedKeysJson = new JSONObject(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON);
    trustedKeysJson
        .getJSONArray("keys")
        .getJSONObject(0)
        .put("base64", ALTERNATE_PUBLIC_SIGNING_KEY);

    RewardedAdsVerifier verifier =
        new RewardedAdsVerifier.Builder()
            .setVerifyingPublicKeys(trustedKeysJson.toString())
            .build();

    try {
      verifier.verify(signUrl(REWARD_URL, GOOGLE_SIGNING_PRIVATE_KEY_PKCS8_BASE64, KEY_ID));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertEquals("Invalid signature", e.getMessage());
    }
  }

  @Test
  public void testShouldFailIfKeyIdNotFound() throws Exception {
    RewardedAdsVerifier verifier =
        new RewardedAdsVerifier.Builder()
            .setVerifyingPublicKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .build();

    try {
      verifier.verify(signUrl(REWARD_URL, GOOGLE_SIGNING_PRIVATE_KEY_PKCS8_BASE64, KEY_ID + 1));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.getMessage().contains("cannot find verifying key with key id"));
    }
  }

  @Test
  public void testShouldFailIfSignedMessageWasChanged() throws Exception {
    RewardedAdsVerifier verifier =
        new RewardedAdsVerifier.Builder()
            .setVerifyingPublicKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .build();
    byte[] validSignedUrl =
        signUrl(REWARD_URL, GOOGLE_SIGNING_PRIVATE_KEY_PKCS8_BASE64, KEY_ID).getBytes(UTF_8);
    for (int i = REWARD_HOST_AND_PATH.length(); i < REWARD_URL.length(); i++) {
      byte[] modifiedUrl = Arrays.copyOf(validSignedUrl, validSignedUrl.length);
      modifiedUrl[i] = (byte) (modifiedUrl[i] ^ 0xff);
      try {
        verifier.verify(new String(modifiedUrl, UTF_8));
        fail("Expected GeneralSecurityException");
      } catch (GeneralSecurityException e) {
        assertEquals("Invalid signature", e.getMessage());
      }
    }
  }

  @Test
  public void testShouldFailIfSignatureWasChanged() throws Exception {
    EcdsaSignJce signer =
        new EcdsaSignJce(
            EllipticCurves.getEcPrivateKey(Base64.decode(GOOGLE_SIGNING_PRIVATE_KEY_PKCS8_BASE64)),
            "SHA256WithECDSA");
    RewardedAdsVerifier verifier =
        new RewardedAdsVerifier.Builder()
            .setVerifyingPublicKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .build();

    byte[] validSig = signer.sign(REWARD_URL.getBytes(UTF_8));
    for (int i = 0; i < validSig.length; i++) {
      byte[] modifiedSig = Arrays.copyOf(validSig, validSig.length);
      modifiedSig[i] = (byte) (modifiedSig[i] ^ 0xff);
      String modifiedUrl = buildUrl(REWARD_URL, modifiedSig, KEY_ID);
      try {
        verifier.verify(modifiedUrl);
        fail("Expected GeneralSecurityException");
      } catch (GeneralSecurityException e) {
        // Expected.
        System.out.println(e);
      }
    }
  }

  @Test
  public void testShouldFailWithoutSignature() throws Exception {
    RewardedAdsVerifier verifier =
        new RewardedAdsVerifier.Builder()
            .setVerifyingPublicKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .build();
    try {
      verifier.verify(REWARD_URL);
    } catch (GeneralSecurityException e) {
      assertEquals("needs a signature query parameter", e.getMessage());
    }
  }

  @Test
  public void testShouldFailWithoutKeyId() throws Exception {
    RewardedAdsVerifier verifier =
        new RewardedAdsVerifier.Builder()
            .setVerifyingPublicKeys(GOOGLE_VERIFYING_PUBLIC_KEYS_JSON)
            .build();
    try {
      verifier.verify(
          new StringBuilder(REWARD_URL)
              .append("&")
              .append(RewardedAdsVerifier.SIGNATURE_PARAM_NAME)
              .append("foo")
              .toString());
    } catch (GeneralSecurityException e) {
      assertEquals("needs a key_id query parameter", e.getMessage());
    }
  }
}
