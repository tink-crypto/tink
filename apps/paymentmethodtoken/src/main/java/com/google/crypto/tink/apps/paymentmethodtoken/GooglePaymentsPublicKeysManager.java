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

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.concurrent.GuardedBy;
import org.joda.time.Instant;

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

  /** Pattern for the max-age header element of Cache-Control. */
  private static final Pattern MAX_AGE_PATTERN = Pattern.compile("\\s*max-age\\s*=\\s*(\\d+)\\s*");

  private final Executor backgroundExecutor;
  private final HttpTransport httpTransport;
  private final Object fetchKeysLock;
  private final Object instanceStateLock;
  private final String keysUrl;

  @GuardedBy("instanceStateLock")
  private Runnable pendingRefreshRunnable;

  @GuardedBy("instanceStateLock")
  private String cachedTrustedSigningKeysJson;

  @GuardedBy("instanceStateLock")
  private long cachedTimeInMillis;

  @GuardedBy("instanceStateLock")
  private long cacheExpirationDurationInMillis;

  GooglePaymentsPublicKeysManager(
      Executor backgroundExecutor, HttpTransport httpTransport, String keysUrl) {
    this.backgroundExecutor = backgroundExecutor;
    this.httpTransport = httpTransport;
    this.instanceStateLock = new Object();
    this.fetchKeysLock = new Object();
    this.keysUrl = keysUrl;
    this.cachedTimeInMillis = Long.MIN_VALUE;
    this.cacheExpirationDurationInMillis = 0;
  }

  /**
   * Returns a string containing a JSON with the Google public signing keys.
   *
   * <p>Meant to be called by {@link PaymentMethodTokenRecipient}.
   */
  String getTrustedSigningKeysJson() throws IOException {
    synchronized (instanceStateLock) {
      // Checking and using the cache if required.
      if (hasNonExpiredKeyCached()) {
        // Proactively triggering a refresh if we are close to the cache expiration.
        if (shouldProactivelyRefreshKeysInBackground()) {
          refreshInBackground();
        }
        return cachedTrustedSigningKeysJson;
      }
    }

    // Acquiring the fetch lock so we don't have multiple threads trying to fetch from the
    // server at the same time.
    synchronized (fetchKeysLock) {
      // It is possible that some other thread performed the fetch already and we don't need
      // to fetch anymore, so double checking a fetch is still required.
      synchronized (instanceStateLock) {
        if (hasNonExpiredKeyCached()) {
          return cachedTrustedSigningKeysJson;
        }
      }
      // No other thread fetched, so it is up to this thread to fetch.
      return fetchAndCacheKeys();
    }
  }

  @GuardedBy("instanceStateLock")
  private boolean hasNonExpiredKeyCached() {
    long currentTimeInMillis = getCurrentTimeInMillis();
    boolean cachedInFuture = cachedTimeInMillis > currentTimeInMillis;
    boolean cacheExpired =
        cachedTimeInMillis + cacheExpirationDurationInMillis <= currentTimeInMillis;
    return !cacheExpired && !cachedInFuture;
  }

  @GuardedBy("instanceStateLock")
  private boolean shouldProactivelyRefreshKeysInBackground() {
    // At half expiration duration, we should try to refresh.
    return cachedTimeInMillis + (cacheExpirationDurationInMillis / 2) <= getCurrentTimeInMillis();
  }

  /**
   * Returns the current time in milliseconds since epoch.
   *
   * <p>Visible so tests can override it in subclasses.
   */
  long getCurrentTimeInMillis() {
    return Instant.now().getMillis();
  }

  @GuardedBy("fetchKeysLock")
  private String fetchAndCacheKeys() throws IOException {
    long currentTimeInMillis = getCurrentTimeInMillis();
    HttpRequest httpRequest =
        httpTransport.createRequestFactory().buildGetRequest(new GenericUrl(keysUrl));
    HttpResponse httpResponse = httpRequest.execute();
    if (httpResponse.getStatusCode() != HttpStatusCodes.STATUS_CODE_OK) {
      throw new IOException("Unexpected status code = " + httpResponse.getStatusCode());
    }
    String trustedSigningKeysJson;
    InputStream contentStream = httpResponse.getContent();
    try {
      InputStreamReader reader = new InputStreamReader(contentStream, StandardCharsets.UTF_8);
      trustedSigningKeysJson = readerToString(reader);
    } finally {
      contentStream.close();
    }
    synchronized (instanceStateLock) {
      this.cachedTimeInMillis = currentTimeInMillis;
      this.cacheExpirationDurationInMillis =
          getExpirationDurationInSeconds(httpResponse.getHeaders()) * 1000;
      this.cachedTrustedSigningKeysJson = trustedSigningKeysJson;
    }
    return trustedSigningKeysJson;
  }

  /** Reads the contents of a {@link Reader} into a {@link String}. */
  private static String readerToString(Reader reader) throws IOException {
    reader = new BufferedReader(reader);
    StringBuilder stringBuilder = new StringBuilder();
    int c;
    while ((c = reader.read()) != -1) {
      stringBuilder.append((char) c);
    }
    return stringBuilder.toString();
  }

  /**
   * Gets the cache TimeInMillis in seconds. "max-age" in "Cache-Control" header and "Age" header
   * are considered.
   *
   * @param httpHeaders the http header of the response
   * @return the cache TimeInMillis in seconds or zero if the response should not be cached
   */
  long getExpirationDurationInSeconds(HttpHeaders httpHeaders) {
    long expirationDurationInSeconds = 0;
    if (httpHeaders.getCacheControl() != null) {
      for (String arg : httpHeaders.getCacheControl().split(",")) {
        Matcher m = MAX_AGE_PATTERN.matcher(arg);
        if (m.matches()) {
          expirationDurationInSeconds = Long.valueOf(m.group(1));
          break;
        }
      }
    }
    if (httpHeaders.getAge() != null) {
      expirationDurationInSeconds -= httpHeaders.getAge();
    }
    return Math.max(0, expirationDurationInSeconds);
  }

  /** Fetches keys in the background. */
  public void refreshInBackground() {
    Runnable refreshRunnable = newRefreshRunnable();
    synchronized (instanceStateLock) {
      if (pendingRefreshRunnable != null) {
        return;
      }
      pendingRefreshRunnable = refreshRunnable;
    }
    try {
      backgroundExecutor.execute(refreshRunnable);
    } catch (Throwable e) {
      synchronized (instanceStateLock) {
        // Clearing if we were still the pending runnable.
        if (pendingRefreshRunnable == refreshRunnable) {
          pendingRefreshRunnable = null;
        }
      }
      throw e;
    }
  }

  private Runnable newRefreshRunnable() {
    return new Runnable() {
      @Override
      public void run() {
        synchronized (fetchKeysLock) {
          try {
            fetchAndCacheKeys();
          } catch (IOException e) {
            // Failed to fetch the keys. Ok as this was just from the background.
          } finally {
            synchronized (instanceStateLock) {
              // Clearing if we were still the pending runnable.
              if (pendingRefreshRunnable == this) {
                pendingRefreshRunnable = null;
              }
            }
          }
        }
      }
    };
  }

  /** Builder for {@link GooglePaymentsPublicKeysManager}. */
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
        if (instance.httpTransport == httpTransport && instance.keysUrl.equals(keysUrl)) {
          return instance;
        }
      }
      return new GooglePaymentsPublicKeysManager(
          DEFAULT_BACKGROUND_EXECUTOR, httpTransport, keysUrl);
    }
  }
}
