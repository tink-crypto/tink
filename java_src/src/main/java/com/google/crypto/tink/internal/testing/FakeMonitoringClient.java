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

package com.google.crypto.tink.internal.testing;

import com.google.crypto.tink.monitoring.MonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringKeysetInfo;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

/**
 * Fake MonitoringClient.
 *
 * <p>It logs all log and logFailure calls of its logger objects into two lists that can be
 * retrieved later.
 */
public final class FakeMonitoringClient implements MonitoringClient {

  /** LogEntry */
  public static final class LogEntry {
    private final MonitoringKeysetInfo keysetInfo;
    private final MonitoringKeysetInfo.Entry keyInfo;
    private final String primitive;
    private final String api;
    private final int keyId;
    private final long numBytesAsInput;

    private LogEntry(
        MonitoringKeysetInfo keysetInfo,
        MonitoringKeysetInfo.Entry keyInfo,
        String primitive,
        String api,
        int keyId,
        long numBytesAsInput) {
      this.keysetInfo = keysetInfo;
      this.keyInfo = keyInfo;
      this.primitive = primitive;
      this.api = api;
      this.keyId = keyId;
      this.numBytesAsInput = numBytesAsInput;
    }

    public MonitoringKeysetInfo getKeysetInfo() {
      return keysetInfo;
    }

    public MonitoringKeysetInfo.Entry getKeyInfo() {
      return keyInfo;
    }

    public String getPrimitive() {
      return primitive;
    }

    public String getApi() {
      return api;
    }

    public int getKeyId() {
      return keyId;
    }

    public long getNumBytesAsInput() {
      return numBytesAsInput;
    }
  }

  /** LogFailureEntry */
  public static final class LogFailureEntry {
    private final String primitive;
    private final String api;
    private final MonitoringKeysetInfo keysetInfo;

    private LogFailureEntry(
        MonitoringKeysetInfo keysetInfo,
        String primitive,
        String api) {
      this.keysetInfo = keysetInfo;
      this.primitive = primitive;
      this.api = api;
    }

    public String getPrimitive() {
      return primitive;
    }

    public String getApi() {
      return api;
    }

    public MonitoringKeysetInfo getKeysetInfo() {
      return keysetInfo;
    }
  }

  private final List<LogEntry> logEntries = new ArrayList<>();
  private final List<LogFailureEntry> logFailureEntries = new ArrayList<>();

  private synchronized void addLogEntry(LogEntry entry) {
    logEntries.add(entry);
  }

  private synchronized void addLogFailureEntry(LogFailureEntry entry) {
    logFailureEntries.add(entry);
  }

  private final class Logger implements MonitoringClient.Logger {
    private final MonitoringKeysetInfo keysetInfo;
    private final HashMap<Integer, MonitoringKeysetInfo.Entry> entries;
    private final String primitive;
    private final String api;

    @Override
    public void log(int keyId, long numBytesAsInput) {
      if (!entries.containsKey(keyId)) {
        throw new IllegalStateException("keyId not found in keysetInfo: " + keyId);
      }
      addLogEntry(
          new LogEntry(keysetInfo, entries.get(keyId), primitive, api, keyId, numBytesAsInput));
    }

    @Override
    public void logFailure() {
      addLogFailureEntry(new LogFailureEntry(keysetInfo, primitive, api));
    }

    private Logger(MonitoringKeysetInfo keysetInfo, String primitive, String api) {
      this.keysetInfo = keysetInfo;
      this.primitive = primitive;
      this.api = api;
      entries = new HashMap<>();
      for (MonitoringKeysetInfo.Entry entry : keysetInfo.getEntries()) {
        entries.put(entry.getKeyId(), entry);
      }
    }
  }

  public FakeMonitoringClient() {
  }

  @Override
  public Logger createLogger(MonitoringKeysetInfo keysetInfo, String primitive, String api) {
    return new Logger(keysetInfo, primitive, api);
  }

  /** Clears all log and log failure entries. */
  public synchronized void clear() {
    logEntries.clear();
    logFailureEntries.clear();
  }

  /** Returns all log entries. */
  public synchronized List<LogEntry> getLogEntries() {
    return Collections.unmodifiableList(logEntries);
  }

  /** Returns all log failure entries. */
  public synchronized List<LogFailureEntry> getLogFailureEntries() {
    return Collections.unmodifiableList(logFailureEntries);
  }
}
