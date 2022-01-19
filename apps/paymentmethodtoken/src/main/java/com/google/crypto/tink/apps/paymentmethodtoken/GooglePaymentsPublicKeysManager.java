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

import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.crypto.tink.util.KeysDownloader;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Thread-safe Google Payments public key manager.
 *
 * <p>For best performance, use the {@link GooglePaymentsPublicKeysManager#INSTANCE_PRODUCTION} for
 * production environment or {@link GooglePaymentsPublicKeysManager#INSTANCE_TEST} for test
 * environment.
 *
 * <p>If you need extra customizations for your use, we recommend you to use {@link
 * GooglePaymentsPublicKeysManager.Builder} to construct an instance and keep it as a singleton in a
 * static final variable across requests.
 *
 * <p>When initializing your server, we also recommend that you call {@link #refreshInBackground()}
 * to proactively fetch the keys.
 *
 * @since 1.0.0
 */
public class GooglePaymentsPublicKeysManager {
  /** Default HTTP transport used by this class. */
  public static final NetHttpTransport DEFAULT_HTTP_TRANSPORT =
      new NetHttpTransport.Builder().build();
  /** URL to fetch keys for environment production. */
  public static final String KEYS_URL_PRODUCTION =
      "https://payments.developers.google.com/paymentmethodtoken/keys.json";
  /** URL to fetch keys for environment test. */
  public static final String KEYS_URL_TEST =
      "https://payments.developers.google.com/paymentmethodtoken/test/keys.json";

  private static final Executor DEFAULT_BACKGROUND_EXECUTOR = Executors.newCachedThreadPool();

  private final KeysDownloader downloader;

  /**
   * Instance configured to talk to fetch keys from production environment (from {@link
   * GooglePaymentsPublicKeysManager#KEYS_URL_PRODUCTION}).
   */
  public static final GooglePaymentsPublicKeysManager INSTANCE_PRODUCTION =
      new GooglePaymentsPublicKeysManager(
          DEFAULT_BACKGROUND_EXECUTOR, DEFAULT_HTTP_TRANSPORT, KEYS_URL_PRODUCTION);
  /**
   * Instance configured to talk to fetch keys from test environment (from {@link
   * GooglePaymentsPublicKeysManager#KEYS_URL_TEST}).
   */
  public static final GooglePaymentsPublicKeysManager INSTANCE_TEST =
      new GooglePaymentsPublicKeysManager(
          DEFAULT_BACKGROUND_EXECUTOR, DEFAULT_HTTP_TRANSPORT, KEYS_URL_TEST);

  GooglePaymentsPublicKeysManager(
      Executor backgroundExecutor, HttpTransport httpTransport, String keysUrl) {
    this.downloader =
        new KeysDownloader.Builder()
            .setUrl(keysUrl)
            .setExecutor(backgroundExecutor)
            .setHttpTransport(httpTransport)
            .build();
  }

  HttpTransport getHttpTransport() {
    return downloader.getHttpTransport();
  }

  String getUrl() {
    return downloader.getUrl();
  }

  /**
   * Returns a string containing a JSON with the Google public signing keys.
   *
   * <p>Meant to be called by {@link PaymentMethodTokenRecipient}.
   */
  public String getTrustedSigningKeysJson() throws IOException {
    return this.downloader.download();
  }

  /** Fetches keys in the background. */
  public void refreshInBackground() {
    downloader.refreshInBackground();
  }

  /**
   * Builder for {@link GooglePaymentsPublicKeysManager}.
   *
   * @since 1.0.0
   */
  public static class Builder {
    private HttpTransport httpTransport = DEFAULT_HTTP_TRANSPORT;
    private String keysUrl = KEYS_URL_PRODUCTION;

    public Builder setKeysUrl(String keysUrl) {
      this.keysUrl = keysUrl;
      return this;
    }

    /**
     * Sets the HTTP transport.
     *
     * <p>You generally should not need to set a custom transport as the default transport {@link
     * GooglePaymentsPublicKeysManager#DEFAULT_HTTP_TRANSPORT} should be suited for most use cases.
     */
    public Builder setHttpTransport(HttpTransport httpTransport) {
      this.httpTransport = httpTransport;
      return this;
    }

    public GooglePaymentsPublicKeysManager build() {
      // If all parameters are equal to the existing singleton instances, returning them instead.
      // This is more a safe guard if users of this class construct a new class and forget to
      // save in a singleton.
      for (GooglePaymentsPublicKeysManager instance :
          Arrays.asList(INSTANCE_PRODUCTION, INSTANCE_TEST)) {
        if (instance.getHttpTransport() == httpTransport && instance.getUrl().equals(keysUrl)) {
          return instance;
        }
      }
      return new GooglePaymentsPublicKeysManager(
          DEFAULT_BACKGROUND_EXECUTOR, httpTransport, keysUrl);
    }
  }
}
