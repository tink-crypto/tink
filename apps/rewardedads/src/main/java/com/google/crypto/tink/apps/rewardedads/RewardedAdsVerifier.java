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

import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.util.KeysDownloader;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * An implementation of the verifier side of Server-Side Verification of Google AdMob Rewarded Ads.
 *
 * <p>Typical usage:
 *
 * <pre>{@code
 * RewardedAdsVerifier verifier = new RewardedAdsVerifier.Builder()
 *     .fetchVerifyingPublicKeysWith(
 *         RewardedAdsVerifier.KEYS_DOWNLOADER_INSTANCE_PROD)
 *     .build();
 * String rewardUrl = ...;
 * verifier.verify(rewardUrl);
 * }</pre>
 *
 * <p>This usage ensures that you always have the latest public keys, even when the keys were
 * recently rotated. It will fetch and cache the latest public keys from {#PUBLIC_KEYS_URL_PROD}.
 * When the cache expires, it will re-fetch the public keys. When initializing your server, we also
 * recommend that you call {@link KeysDownloader#refreshInBackground()} of {@link
 * RewardedAdsVerifier.KEYS_DOWNLOADER_INSTANCE_PROD} to proactively fetch the public keys.
 *
 * <p>If you've already downloaded the public keys and have other means to manage key rotation, you
 * can use {@link RewardedAdsVerifier.Builder#setVerifyingPublicKeys} to set the public keys. The
 * Builder also allows you to customize other properties.
 */
public final class RewardedAdsVerifier {
  /** Default HTTP transport used by this class. */
  private static final NetHttpTransport DEFAULT_HTTP_TRANSPORT =
      new NetHttpTransport.Builder().build();

  private static final Executor DEFAULT_BACKGROUND_EXECUTOR = Executors.newCachedThreadPool();
  private final List<VerifyingPublicKeysProvider> verifyingPublicKeysProviders;

  public static final String SIGNATURE_PARAM_NAME = "signature=";
  public static final String KEY_ID_PARAM_NAME = "key_id=";

  /** URL to fetch keys for environment production. */
  public static final String PUBLIC_KEYS_URL_PROD =
      "https://www.gstatic.com/admob/reward/verifier-keys.json";

  /** URL to fetch keys for environment test. */
  public static final String PUBLIC_KEYS_URL_TEST =
      "https://www.gstatic.com/admob/reward/verifier-keys-test.json";

  /**
   * Instance configured to talk to fetch keys from production environment (from {@link
   * KeysDownloader#PUBLIC_KEYS_URL_PROD}).
   */
  public static final KeysDownloader KEYS_DOWNLOADER_INSTANCE_PROD =
      new KeysDownloader(DEFAULT_BACKGROUND_EXECUTOR, DEFAULT_HTTP_TRANSPORT, PUBLIC_KEYS_URL_PROD);
  /**
   * Instance configured to talk to fetch keys from test environment (from {@link
   * KeysDownloader#KEYS_URL_TEST}).
   */
  public static final KeysDownloader KEYS_DOWNLOADER_INSTANCE_TEST =
      new KeysDownloader(DEFAULT_BACKGROUND_EXECUTOR, DEFAULT_HTTP_TRANSPORT, PUBLIC_KEYS_URL_TEST);

  RewardedAdsVerifier(List<VerifyingPublicKeysProvider> verifyingPublicKeysProviders)
      throws GeneralSecurityException {
    if (verifyingPublicKeysProviders == null || verifyingPublicKeysProviders.isEmpty()) {
      throw new IllegalArgumentException(
          "must set at least one way to get verifying key using"
              + " Builder.fetchVerifyingPublicKeysWith or Builder.setVerifyingPublicKeys");
    }
    this.verifyingPublicKeysProviders = verifyingPublicKeysProviders;
  }

  private RewardedAdsVerifier(Builder builder) throws GeneralSecurityException {
    this(builder.verifyingPublicKeysProviders);
  }

  /**
   * Verifies that {@code rewardUrl} has a valid signature.
   *
   * <p>This method requires that the name of the last two query parameters of {@code rewardUrl} are
   * {@link #SIGNATURE_PARAM_NAME} and {@link #KEY_ID_PARAM_NAME} in that order.
   */
  public void verify(String rewardUrl) throws GeneralSecurityException {
    URI uri;
    try {
      uri = new URI(rewardUrl);
    } catch (URISyntaxException ex) {
      throw new GeneralSecurityException(ex);
    }
    String queryString = uri.getQuery();
    int i = queryString.indexOf(SIGNATURE_PARAM_NAME);
    if (i <= 0 || queryString.charAt(i - 1) != '&') {
      throw new GeneralSecurityException(
          "signature and key id must be the last two query parameters");
    }
    byte[] tbsData =
        queryString
            .substring(0, i - 1 /* i - 1 instead of i because of & */)
            .getBytes(Charset.forName("UTF-8"));

    String sigAndKeyId = queryString.substring(i);
    i = sigAndKeyId.indexOf(KEY_ID_PARAM_NAME);
    if (i == -1 || sigAndKeyId.charAt(i - 1) != '&') {
      throw new GeneralSecurityException(
          "signature and key id must be the last two query parameters");
    }
    String sig =
        sigAndKeyId.substring(
            SIGNATURE_PARAM_NAME.length(), i - 1 /* i - 1 instead of i because of & */);

    // We don't have to check that keyId is the last parameter, because the long conversion would
    // fail anyway if there's any trailing data.
    try {
      long keyId = Long.parseLong(sigAndKeyId.substring(i + KEY_ID_PARAM_NAME.length()));
      verify(tbsData, keyId, Base64.urlSafeDecode(sig));
    } catch (NumberFormatException ex) {
      throw new GeneralSecurityException("key_id must be a long");
    }
  }

  private void verify(final byte[] tbs, long keyId, final byte[] signature)
      throws GeneralSecurityException {
    boolean foundKeyId = false;
    for (VerifyingPublicKeysProvider provider : verifyingPublicKeysProviders) {
      Map<Long, ECPublicKey> publicKeys = provider.get();
      if (publicKeys.containsKey(keyId)) {
        foundKeyId = true;
        ECPublicKey publicKey = publicKeys.get(keyId);
        EcdsaVerifyJce verifier = new EcdsaVerifyJce(publicKey, HashType.SHA256, EcdsaEncoding.DER);
        verifier.verify(signature, tbs);
      }
    }
    if (!foundKeyId) {
      throw new GeneralSecurityException("cannot find verifying key with key id: " + keyId);
    }
  }

  /** Builder for RewardedAdsVerifier. */
  public static class Builder {
    private final List<VerifyingPublicKeysProvider> verifyingPublicKeysProviders =
        new ArrayList<VerifyingPublicKeysProvider>();

    public Builder() {}

    /**
     * Fetches verifying public keys of the sender using {@link KeysDownloader}.
     *
     * <p>This is the preferred method of specifying the verifying public keys.
     */
    public Builder fetchVerifyingPublicKeysWith(final KeysDownloader downloader)
        throws GeneralSecurityException {
      this.verifyingPublicKeysProviders.add(
          new VerifyingPublicKeysProvider() {
            @Override
            public Map<Long, ECPublicKey> get() throws GeneralSecurityException {
              try {
                return parsePublicKeysJson(downloader.download());
              } catch (IOException e) {
                throw new GeneralSecurityException("Failed to fetch keys!", e);
              }
            }
          });
      return this;
    }

    /**
     * Sets the trusted verifying public keys of the sender.
     *
     * <p><b>IMPORTANT</b>: Instead of using this method to set the verifying public keys of the
     * sender, prefer calling {@link #fetchVerifyingPublicKeysWith} passing it an instance of {@link
     * KeysDownloader}. It will take care of fetching fresh keys and caching in memory. Only use
     * this method if you can't use {@link #fetchVerifyingPublicKeysWith} and be aware you will need
     * to handle key rotations yourself.
     *
     * <p>The given string is a JSON object formatted like the following:
     *
     * <pre>
     * {
     *   "keys": [
     *     {
     *       keyId: 1916455855,
     *       pem: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUaWMKcBHWdhUE+DncSIHhFCLLEln\nUs0LB9oanZ4K/FNICIM8ltS4nzc9yjmhgVQOlmSS6unqvN9t8sqajRTPcw==\n-----END PUBLIC KEY-----"
     *       base64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUaWMKcBHWdhUE+DncSIHhFCLLElnUs0LB9oanZ4K/FNICIM8ltS4nzc9yjmhgVQOlmSS6unqvN9t8sqajRTPcw=="
     *     },
     *     {
     *       keyId: 3901585526,
     *       pem: "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEtxg2BsK/fllIeADtLspezS6YfHFWXZ8tiJncm8LDBa/NxEC84akdWbWDCUrMMGIV27/3/e7UuKSEonjGvaDUsw==\n-----END PUBLIC KEY-----"
     *       base64: "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEtxg2BsK/fllIeADtLspezS6YfHFWXZ8tiJncm8LDBa/NxEC84akdWbWDCUrMMGIV27/3/e7UuKSEonjGvaDUsw=="
     *     },
     *   ],
     * }
     * </pre>
     *
     * <p>Each public key will be a base64 (no wrapping, padded) version of the key encoded in ASN.1
     * type SubjectPublicKeyInfo defined in the X.509 standard.
     */
    public Builder setVerifyingPublicKeys(final String publicKeysJson)
        throws GeneralSecurityException {
      this.verifyingPublicKeysProviders.add(
          new VerifyingPublicKeysProvider() {
            @Override
            public Map<Long, ECPublicKey> get() throws GeneralSecurityException {
              return parsePublicKeysJson(publicKeysJson);
            }
          });
      return this;
    }

    /**
     * Adds a verifying public key of the sender.
     *
     * <p><b>IMPORTANT</b>: Instead of using this method to set the verifying public keys of the
     * sender, prefer calling {@link #fetchVerifyingPublicKeysWith} passing it an instance of {@link
     * KeysDownloader}. It will take care of fetching fresh keys and caching in memory. Only use
     * this method if you can't use {@link #fetchVerifyingPublicKeysWith} and be aware you will need
     * to handle Google key rotations yourself.
     *
     * <p>The public key is a base64 (no wrapping, padded) version of the key encoded in ASN.1 type
     * SubjectPublicKeyInfo defined in the X.509 standard.
     *
     * <p>Multiple keys may be added. This utility will then verify any message signed with any of
     * the private keys corresponding to the public keys added. Adding multiple keys is useful for
     * handling key rotation.
     */
    public Builder addVerifyingPublicKey(final long keyId, final String val)
        throws GeneralSecurityException {
      this.verifyingPublicKeysProviders.add(
          new VerifyingPublicKeysProvider() {
            @Override
            public Map<Long, ECPublicKey> get() throws GeneralSecurityException {
              return Collections.singletonMap(
                  keyId, EllipticCurves.getEcPublicKey(Base64.decode(val)));
            }
          });
      return this;
    }

    /**
     * Adds a verifying public key of the sender.
     *
     * <p><b>IMPORTANT</b>: Instead of using this method to set the verifying public keys of the
     * sender, prefer calling {@link #fetchVerifyingPublicKeysWith} passing it an instance of {@link
     * KeysDownloader}. It will take care of fetching fresh keys and caching in memory. Only use
     * this method if you can't use {@link #fetchVerifyingPublicKeysWith} and be aware you will need
     * to handle Google key rotations yourself.
     */
    public Builder addVerifyingPublicKey(final long keyId, final ECPublicKey val)
        throws GeneralSecurityException {
      this.verifyingPublicKeysProviders.add(
          new VerifyingPublicKeysProvider() {
            @Override
            public Map<Long, ECPublicKey> get() throws GeneralSecurityException {
              return Collections.singletonMap(keyId, val);
            }
          });
      return this;
    }

    public RewardedAdsVerifier build() throws GeneralSecurityException {
      return new RewardedAdsVerifier(this);
    }
  }

  private static Map<Long, ECPublicKey> parsePublicKeysJson(String publicKeysJson)
      throws GeneralSecurityException {
    Map<Long, ECPublicKey> publicKeys = new HashMap<>();
    try {
      JSONArray keys = new JSONObject(publicKeysJson).getJSONArray("keys");
      for (int i = 0; i < keys.length(); i++) {
        JSONObject key = keys.getJSONObject(i);
        publicKeys.put(
            key.getLong("keyId"),
            EllipticCurves.getEcPublicKey(Base64.decode(key.getString("base64"))));
      }
    } catch (JSONException e) {
      throw new GeneralSecurityException("failed to extract trusted signing public keys", e);
    }
    if (publicKeys.isEmpty()) {
      throw new GeneralSecurityException("no trusted keys are available for this protocol version");
    }
    return publicKeys;
  }

  private interface VerifyingPublicKeysProvider {
    Map<Long, ECPublicKey> get() throws GeneralSecurityException;
  }
}
