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

package com.google.crypto.tink.internal;

import com.google.crypto.tink.monitoring.MonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringKeysetInfo;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A Registry for MonitoringClient.
 */
public final class MutableMonitoringRegistry {
  private static final MutableMonitoringRegistry GLOBAL_INSTANCE =
      new MutableMonitoringRegistry();

  public static MutableMonitoringRegistry globalInstance() {
    return GLOBAL_INSTANCE;
  }

  private static class DoNothingClient implements MonitoringClient {
    private static class DoNothingLogger implements MonitoringClient.Logger {
      @Override
      public void log(int keyId, long numBytesAsInput) {}

      @Override
      public void logFailure() {}
    }
    private static final DoNothingLogger DO_NOTHING_LOGGER = new DoNothingLogger();

    @Override
    public MonitoringClient.Logger createLogger(
        MonitoringKeysetInfo keysetInfo, String primitive, String api) {
      return DO_NOTHING_LOGGER;
    }
  }
  private static final DoNothingClient DO_NOTHING_CLIENT = new DoNothingClient();

  private final AtomicReference<MonitoringClient> monitoringClient =
      new AtomicReference<>(DO_NOTHING_CLIENT);

  public synchronized void registerMonitoringClient(MonitoringClient client) {
    if (!monitoringClient.get().equals(DO_NOTHING_CLIENT)) {
      throw new IllegalStateException("a monitoring client has already been registered");
    }
    monitoringClient.set(client);
  }

  public MonitoringClient getMonitoringClient() {
    return monitoringClient.get();
  }

  public MutableMonitoringRegistry() {}
}
