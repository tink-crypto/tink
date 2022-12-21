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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link KeysDownloader}. */
@RunWith(JUnit4.class)
public class KeysDownloaderTest {
  private static final long INITIAL_CURRENT_TIME_IN_MILLIS = 1000;

  private CountDownLatch backgroundFetchFinishedLatch;
  private CountDownLatch delayHttpResponseLatch;
  private ExecutorService executor;
  private HttpResponseBuilder httpResponseBuilder;
  private AtomicInteger backgroundFetchStartedCount;
  private AtomicInteger httpTransportGetCount;
  private boolean executorIsAcceptingRunnables;
  private long currentTimeInMillis;

  @Before
  public void setUp() {
    backgroundFetchFinishedLatch = new CountDownLatch(1);
    delayHttpResponseLatch = null;
    executor = Executors.newCachedThreadPool();
    httpResponseBuilder = new HttpResponseBuilder();
    backgroundFetchStartedCount = new AtomicInteger(0);
    httpTransportGetCount = new AtomicInteger(0);
    currentTimeInMillis = INITIAL_CURRENT_TIME_IN_MILLIS;
    executorIsAcceptingRunnables = true;
    TestKeysDownloader.sTestInstance = this;
  }

  @After
  public void tearDown() throws Exception {
    executor.shutdownNow();
    assertTrue(
        "Timed out while waiting for the threadpool to terminate!",
        executor.awaitTermination(1, TimeUnit.SECONDS));
  }

  @Test
  public void builderShouldThrowIllegalArgumentExceptionWhenUrlIsNotHttps() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new KeysDownloader.Builder().setUrl("http://abc").build());
  }

  @Test
  public void shouldFetchKeys() throws Exception {
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys");

    assertEquals("keys", newInstanceForTests().download());
  }

  @Test
  public void shouldThrowOnSuccessHttpResponsesThatAreNotOk() throws Exception {
    httpResponseBuilder =
        new HttpResponseBuilder().setStatusCode(HttpStatusCodes.STATUS_CODE_NO_CONTENT);
    KeysDownloader instance = newInstanceForTests();

    IOException expected = assertThrows(IOException.class, instance::download);
    assertEquals(
        "Unexpected status code = " + HttpStatusCodes.STATUS_CODE_NO_CONTENT,
        expected.getMessage());
  }

  @Test
  public void shouldThrowOnNonSuccessHttpResponses() throws Exception {
    httpResponseBuilder =
        new HttpResponseBuilder().setStatusCode(HttpStatusCodes.STATUS_CODE_NO_CONTENT);
    KeysDownloader instance = newInstanceForTests();

    IOException expected = assertThrows(IOException.class, instance::download);
    assertTrue(
        "Message "
            + expected.getMessage()
            + " should contain "
            + HttpStatusCodes.STATUS_CODE_NO_CONTENT,
        expected.getMessage().contains(Integer.toString(HttpStatusCodes.STATUS_CODE_NO_CONTENT)));
  }

  @Test
  public void shouldCacheKeysOnFetches() throws Exception {
    KeysDownloader instance = newInstanceForTests();
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys1");
    // Fetched and cached keys
    assertEquals("keys1", instance.download());
    // Keys changed
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys2");

    // Old keys are returned
    assertEquals("keys1", instance.download());
  }

  @Test
  public void shouldFetchKeysAgainIfNoCacheControlHeadersAreSent() throws Exception {
    KeysDownloader instance = newInstanceForTests();
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys1").clearCacheControl();
    // Fetched and cached keys
    assertEquals("keys1", instance.download());
    // Keys changed
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys2");

    // New keys are fetched and returned
    assertEquals("keys2", instance.download());
  }

  @Test
  public void shouldFetchKeysAgainAfterExpiration() throws Exception {
    KeysDownloader instance = newInstanceForTests();
    httpResponseBuilder =
        new HttpResponseBuilder().setContent("keys1").setCacheControlWithMaxAgeInSeconds(3L);
    // Fetched and cached keys
    assertEquals("keys1", instance.download());
    // Keys changed
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys2");
    // 3 seconds later ...
    currentTimeInMillis += 3000L;

    // New keys are fetched and returned
    assertEquals("keys2", instance.download());
  }

  @Test
  public void shouldReturnCachedKeysBeforeExpiration() throws Exception {
    KeysDownloader instance = newInstanceForTests();
    httpResponseBuilder =
        new HttpResponseBuilder().setContent("keys1").setCacheControlWithMaxAgeInSeconds(3L);
    // Fetched and cached keys
    assertEquals("keys1", instance.download());
    // Keys changed
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys2");
    // 3 seconds - 1ms later ...
    currentTimeInMillis += 3000L - 1;

    // Old keys are sill returned
    assertEquals("keys1", instance.download());
  }

  @Test
  public void shouldFetchKeysAgainAfterExpirationAccountingForAgeHeader() throws Exception {
    KeysDownloader instance = newInstanceForTests();
    httpResponseBuilder =
        new HttpResponseBuilder()
            .setContent("keys1")
            .setCacheControlWithMaxAgeInSeconds(3L)
            .setAgeInSeconds(1L);
    // Fetched and cached keys
    assertEquals("keys1", instance.download());
    // Keys changed
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys2");
    // 2 seconds later ...
    currentTimeInMillis += 2000L;

    // New keys are fetched and returned
    assertEquals("keys2", instance.download());
  }

  @Test
  public void shouldReturnCachedKeysBeforeExpirationAccountingForAgeHeader() throws Exception {
    KeysDownloader instance = newInstanceForTests();
    httpResponseBuilder =
        new HttpResponseBuilder()
            .setContent("keys1")
            .setCacheControlWithMaxAgeInSeconds(3L)
            .setAgeInSeconds(1L);
    // Fetched and cached keys
    assertEquals("keys1", instance.download());
    // Keys changed
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys2");
    // 2 seconds - 1ms later ...
    currentTimeInMillis += 2000L - 1;

    // Old keys are sill returned
    assertEquals("keys1", instance.download());
  }

  @Test
  public void shouldTriggerBackgroundRefreshHalfWayThroughExpiration() throws Exception {
    KeysDownloader instance = newInstanceForTests();
    httpResponseBuilder =
        new HttpResponseBuilder().setContent("keys1").setCacheControlWithMaxAgeInSeconds(3L);
    // Fetched and cached keys
    assertEquals("keys1", instance.download());
    // Keys changed
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys2");
    // 1.5 seconds later ...
    currentTimeInMillis += 1500L;
    // Old keys are sill returned, but a background fetch is initiated
    assertEquals("keys1", instance.download());
    // Wait background fetch to complete
    waitForLatch(backgroundFetchFinishedLatch);
    // 10ms later ...
    currentTimeInMillis += 10;
    // Keys changed again
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys3");

    // Keys fetched in the background are used
    assertEquals("keys2", instance.download());
    // Single background fetch should have been triggered
    assertEquals(1, backgroundFetchStartedCount.get());
  }

  @Test
  public void shouldNotTriggerBackgroundRefreshBeforeHalfWayThroughExpiration() throws Exception {
    KeysDownloader instance = newInstanceForTests();
    httpResponseBuilder =
        new HttpResponseBuilder().setContent("keys1").setCacheControlWithMaxAgeInSeconds(3L);
    // Fetched and cached keys
    assertEquals("keys1", instance.download());
    // Keys changed
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys2");
    // 1.5 seconds - 1ms later ...
    currentTimeInMillis += 1500L - 1;

    // Old keys are sill returned
    assertEquals("keys1", instance.download());
    // No background fetch should have been triggered
    assertEquals(0, backgroundFetchStartedCount.get());
  }

  @Test
  public void shouldPerformBackgroundRefreshWhenRequestedAndHaveCacheKeys() throws Exception {
    KeysDownloader instance = newInstanceForTests();
    httpResponseBuilder =
        new HttpResponseBuilder().setContent("keys1").setCacheControlWithMaxAgeInSeconds(3L);
    // Fetched and cache keys
    instance.refreshInBackground();
    // Wait background fetch to complete
    waitForLatch(backgroundFetchFinishedLatch);
    // Keys changed
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys2");

    // Keys fetched in the background are used
    assertEquals("keys1", instance.download());
    // Single background fetch should have been triggered
    assertEquals(1, backgroundFetchStartedCount.get());
    // Single http fetch should have been triggered
    assertEquals(1, httpTransportGetCount.get());
  }

  @Test
  public void shouldPerformMultipleRefreshesWhenRequested() throws Exception {
    KeysDownloader instance = newInstanceForTests();
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys1");
    instance.refreshInBackground();
    waitForLatch(backgroundFetchFinishedLatch);
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys2");
    backgroundFetchFinishedLatch = new CountDownLatch(1);
    instance.refreshInBackground();
    waitForLatch(backgroundFetchFinishedLatch);

    // Keys fetched in the background are used
    assertEquals("keys2", instance.download());
    // Multiple background fetch should have been triggered
    assertEquals(2, backgroundFetchStartedCount.get());
    // Multiple http fetch should have been triggered
    assertEquals(2, httpTransportGetCount.get());
  }

  @Test
  public void shouldPerformRefreshAfterExecutorTransientFailure() throws Exception {
    KeysDownloader instance = newInstanceForTests();
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys1");
    Object unused = instance.download();
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys2");
    // Executor temporarily full, rejecting new Runnable instances
    executorIsAcceptingRunnables = false;
    assertThrows(RejectedExecutionException.class, instance::refreshInBackground);
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys3");
    // Executor available again, accepting new Runnable instances
    executorIsAcceptingRunnables = true;
    instance.refreshInBackground();
    waitForLatch(backgroundFetchFinishedLatch);

    // Keys fetched in the background are used
    assertEquals("keys3", instance.download());
    // Only a single background fetch should have started
    assertEquals(1, backgroundFetchStartedCount.get());
  }

  @Test
  public void shouldFetchOnlyOnceWhenMultipleThreadsTryToGetKeys() throws Exception {
    final KeysDownloader instance = newInstanceForTests();
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys");
    List<FutureTask<String>> tasks = new ArrayList<>();
    for (int i = 0; i < 10; i++) {
      tasks.add(
          new FutureTask<String>(
              new Callable<String>() {
                @Override
                public String call() throws Exception {
                  return instance.download();
                }
              }));
    }

    // Force the HTTP responses to be delayed until the latch goes down to 0.
    delayHttpResponseLatch = new CountDownLatch(1);
    // Execute the all fetches in parallel.
    for (FutureTask<String> task : tasks) {
      executor.execute(task);
    }
    // Releasing the response.
    delayHttpResponseLatch.countDown();

    for (FutureTask<String> task : tasks) {
      assertEquals("keys", task.get(5, TimeUnit.SECONDS));
    }
    // Should only have hit the network once.
    assertEquals(1, httpTransportGetCount.get());
  }

  @Test
  public void
      shouldFetchOnlyOnceInBackgroundHalfWayThroughExpirationWhenMultipleThreadsTryToGetKeys()
          throws Exception {
    final KeysDownloader instance = newInstanceForTests();
    httpResponseBuilder =
        new HttpResponseBuilder().setContent("keys1").setCacheControlWithMaxAgeInSeconds(3L);
    // Fetched and cached keys
    assertEquals("keys1", instance.download());
    // Keys changed
    httpResponseBuilder = new HttpResponseBuilder().setContent("keys2");
    // 1.5 seconds later
    currentTimeInMillis += 1500L;
    List<FutureTask<String>> tasks = new ArrayList<>();
    for (int i = 0; i < 10; i++) {
      tasks.add(
          new FutureTask<String>(
              new Callable<String>() {
                @Override
                public String call() throws Exception {
                  return instance.download();
                }
              }));
    }
    // Resetting counters
    httpTransportGetCount.set(0);
    backgroundFetchStartedCount.set(0);

    // Force the HTTP responses to be delayed until the latch goes down to 0.
    delayHttpResponseLatch = new CountDownLatch(1);
    // Execute the all fetches in parallel.
    for (FutureTask<String> task : tasks) {
      executor.execute(task);
    }
    // Wait for all of them to complete (will use old keys that were cached)
    for (FutureTask<String> task : tasks) {
      assertEquals("keys1", task.get(5, TimeUnit.SECONDS));
    }
    // Releasing the response.
    delayHttpResponseLatch.countDown();
    // Waiting background fetch to finish
    waitForLatch(backgroundFetchFinishedLatch);

    // Only a single background fetch should have been triggered
    assertEquals(1, backgroundFetchStartedCount.get());
    // Should only have hit the network once.
    assertEquals(1, httpTransportGetCount.get());
  }

  private static void waitForLatch(CountDownLatch latch) {
    try {
      assertTrue("Timed out!", latch.await(5, TimeUnit.SECONDS));
    } catch (InterruptedException e) {
      throw new RuntimeException(e);
    }
  }

  private TestKeysDownloader newInstanceForTests() {
    return new TestKeysDownloader(
        new Executor() {
          @Override
          public void execute(final Runnable command) {
            if (!executorIsAcceptingRunnables) {
              throw new RejectedExecutionException();
            }
            executor.execute(
                new Runnable() {
                  @Override
                  public void run() {
                    backgroundFetchStartedCount.incrementAndGet();
                    try {
                      command.run();
                    } finally {
                      backgroundFetchFinishedLatch.countDown();
                    }
                  }
                });
          }
        },
        new MockHttpTransport() {
          @Override
          public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
            httpTransportGetCount.incrementAndGet();
            if (delayHttpResponseLatch != null) {
              waitForLatch(delayHttpResponseLatch);
            }
            assertEquals("https://someUrl", url);
            assertEquals("GET", method);
            MockLowLevelHttpRequest request = new MockLowLevelHttpRequest(url);
            request.setResponse(httpResponseBuilder.build());
            return request;
          }
        },
        "https://someUrl");
  }

  private static class TestKeysDownloader extends KeysDownloader {
    private static KeysDownloaderTest sTestInstance;

    TestKeysDownloader(Executor backgroundExecutor, HttpTransport httpTransport, String keysUrl) {
      super(backgroundExecutor, httpTransport, keysUrl);
    }

    @Override
    long getCurrentTimeInMillis() {
      return sTestInstance.currentTimeInMillis;
    }
  }

  private static class HttpResponseBuilder {
    private String content = "content";
    private Long maxAgeInSeconds = 10L;
    private Long ageInSeconds;
    private int statusCode = HttpStatusCodes.STATUS_CODE_OK;

    @CanIgnoreReturnValue
    public HttpResponseBuilder setStatusCode(int statusCode) {
      this.statusCode = statusCode;
      return this;
    }

    @CanIgnoreReturnValue
    public HttpResponseBuilder setContent(String content) {
      this.content = content;
      return this;
    }

    @CanIgnoreReturnValue
    public HttpResponseBuilder setCacheControlWithMaxAgeInSeconds(Long maxAgeInSeconds) {
      this.maxAgeInSeconds = maxAgeInSeconds;
      return this;
    }

    @CanIgnoreReturnValue
    public HttpResponseBuilder clearCacheControl() {
      this.maxAgeInSeconds = null;
      return this;
    }

    @CanIgnoreReturnValue
    public HttpResponseBuilder setAgeInSeconds(Long ageInSeconds) {
      this.ageInSeconds = ageInSeconds;
      return this;
    }

    public MockLowLevelHttpResponse build() {
      MockLowLevelHttpResponse response =
          new MockLowLevelHttpResponse().setContent(content).setStatusCode(statusCode);
      if (ageInSeconds != null) {
        response.addHeader("Age", Long.toString(ageInSeconds));
      }
      if (maxAgeInSeconds != null) {
        response.addHeader("Cache-Control", "public, max-age=" + maxAgeInSeconds);
      }
      return response;
    }
  }
}
