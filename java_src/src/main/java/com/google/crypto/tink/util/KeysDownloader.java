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

package com.google.crypto.tink.util;

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
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Locale;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.concurrent.GuardedBy;
import org.joda.time.Instant;

/**
 * Thread-safe downloader.
 *
 * <p>This class can be used to download keys from a remote HTTPS server.
 *
 * <h3>Usage</h3>
 *
 * <p>Use {@link KeysDownloader.Builder} to construct an instance and keep it as a singleton in a
 * static final variable across requests.
 *
 * <p>When initializing your server, we also recommend that you call {@link #refreshInBackground()}
 * to proactively fetch the data.
 *
 * @since 1.1.0
 */
public class KeysDownloader {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  /** Default HTTP transport used by this class. */
  private static final NetHttpTransport DEFAULT_HTTP_TRANSPORT =
      new NetHttpTransport.Builder().build();

  private static final Executor DEFAULT_BACKGROUND_EXECUTOR = Executors.newCachedThreadPool();

  /** Pattern for the max-age header element of Cache-Control. */
  private static final Pattern MAX_AGE_PATTERN = Pattern.compile("\\s*max-age\\s*=\\s*(\\d+)\\s*");

  private final Executor backgroundExecutor;
  private final HttpTransport httpTransport;
  private final Object fetchDataLock;
  private final Object instanceStateLock;
  private final String url;

  @GuardedBy("instanceStateLock")
  private Runnable pendingRefreshRunnable;

  @GuardedBy("instanceStateLock")
  private String cachedData;

  @GuardedBy("instanceStateLock")
  private long cachedTimeInMillis;

  @GuardedBy("instanceStateLock")
  private long cacheExpirationDurationInMillis;

  public KeysDownloader(Executor backgroundExecutor, HttpTransport httpTransport, String url) {
    validate(url);
    this.backgroundExecutor = backgroundExecutor;
    this.httpTransport = httpTransport;
    this.instanceStateLock = new Object();
    this.fetchDataLock = new Object();
    this.url = url;
    this.cachedTimeInMillis = Long.MIN_VALUE;
    this.cacheExpirationDurationInMillis = 0;
  }

  /**
   * Returns a string containing a JSON with the Google public signing keys.
   *
   * <p>Meant to be called by {@link PaymentMethodTokenRecipient}.
   */
  public String download() throws IOException {
    synchronized (instanceStateLock) {
      // Checking and using the cache if required.
      if (hasNonExpiredDataCached()) {
        // Proactively triggering a refresh if we are close to the cache expiration.
        if (shouldProactivelyRefreshDataInBackground()) {
          refreshInBackground();
        }
        return cachedData;
      }
    }

    // Acquiring the fetch lock so we don't have multiple threads trying to fetch from the
    // server at the same time.
    synchronized (fetchDataLock) {
      // It is possible that some other thread performed the fetch already and we don't need
      // to fetch anymore, so double checking a fetch is still required.
      synchronized (instanceStateLock) {
        if (hasNonExpiredDataCached()) {
          return cachedData;
        }
      }
      // No other thread fetched, so it is up to this thread to fetch.
      return fetchAndCacheData();
    }
  }

  public HttpTransport getHttpTransport() {
    return httpTransport;
  }

  public String getUrl() {
    return url;
  }

  @GuardedBy("instanceStateLock")
  private boolean hasNonExpiredDataCached() {
    long currentTimeInMillis = getCurrentTimeInMillis();
    boolean cachedInFuture = cachedTimeInMillis > currentTimeInMillis;
    boolean cacheExpired =
        cachedTimeInMillis + cacheExpirationDurationInMillis <= currentTimeInMillis;
    return !cacheExpired && !cachedInFuture;
  }

  @GuardedBy("instanceStateLock")
  private boolean shouldProactivelyRefreshDataInBackground() {
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

  @GuardedBy("fetchDataLock")
  private String fetchAndCacheData() throws IOException {
    long currentTimeInMillis = getCurrentTimeInMillis();
    HttpRequest httpRequest =
        httpTransport.createRequestFactory().buildGetRequest(new GenericUrl(url));
    HttpResponse httpResponse = httpRequest.execute();
    if (httpResponse.getStatusCode() != HttpStatusCodes.STATUS_CODE_OK) {
      throw new IOException("Unexpected status code = " + httpResponse.getStatusCode());
    }
    String data;
    InputStream contentStream = httpResponse.getContent();
    try {
      InputStreamReader reader = new InputStreamReader(contentStream, UTF_8);
      data = readerToString(reader);
    } finally {
      contentStream.close();
    }
    synchronized (instanceStateLock) {
      this.cachedTimeInMillis = currentTimeInMillis;
      this.cacheExpirationDurationInMillis =
          getExpirationDurationInSeconds(httpResponse.getHeaders()) * 1000;
      this.cachedData = data;
    }
    return data;
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
        synchronized (fetchDataLock) {
          try {
            fetchAndCacheData();
          } catch (IOException e) {
            // Failed to fetch the data. Ok as this was just from the background.
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

  private static void validate(String url) {
    try {
      URL tmp = new URL(url);
      if (!tmp.getProtocol().toLowerCase(Locale.US).equals("https")) {
        throw new IllegalArgumentException("url must point to a HTTPS server");
      }
    } catch (MalformedURLException ex) {
      throw new IllegalArgumentException(ex);
    }
  }

  /** Builder for {@link KeysDownloader}. */
  public static class Builder {
    private HttpTransport httpTransport = DEFAULT_HTTP_TRANSPORT;
    private Executor executor = DEFAULT_BACKGROUND_EXECUTOR;
    private String url;

    /** Sets the url which must point to a HTTPS server. */
    public Builder setUrl(String val) {
      this.url = val;
      return this;
    }

    /** Sets the background executor. */
    public Builder setExecutor(Executor val) {
      this.executor = val;
      return this;
    }

    /**
     * Sets the HTTP transport.
     *
     * <p>You generally should not need to set a custom transport as the default transport {@link
     * KeysDownloader#DEFAULT_HTTP_TRANSPORT} should be suited for most use cases.
     */
    public Builder setHttpTransport(HttpTransport httpTransport) {
      this.httpTransport = httpTransport;
      return this;
    }

    public KeysDownloader build() {
      if (url == null) {
        throw new IllegalArgumentException("must provide a url with {#setUrl}");
      }
      return new KeysDownloader(executor, httpTransport, url);
    }
  }
}
