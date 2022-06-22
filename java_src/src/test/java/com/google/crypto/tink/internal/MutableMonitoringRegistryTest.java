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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.monitoring.MonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringKeysetInfo;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class MutableMonitoringRegistryTest {

  @Test
  public void defaultClientWorks() throws Exception {
    MutableMonitoringRegistry registry = new MutableMonitoringRegistry();
    MonitoringClient client = registry.getMonitoringClient();
    MonitoringClient.Logger logger = client.createLogger(null, "primitive", "api");
    // We only expect the default client to not throw any exceptions.
    logger.log(123, 42L);
    logger.logFailure();
  }

  private static class StubMonitoringClient implements MonitoringClient {
    @Override
    public MonitoringClient.Logger createLogger(
        MonitoringKeysetInfo keysetInfo, String primitive, String api) {
      return null;
    }
  }

  @Test
  public void testRegisterAndGetMonitoringClient() throws Exception {
    MutableMonitoringRegistry registry = new MutableMonitoringRegistry();
    MonitoringClient client = new StubMonitoringClient();
    registry.registerMonitoringClient(client);
    assertThat(registry.getMonitoringClient()).isEqualTo(client);
  }

  @Test
  public void testRegisterTwiceFails() throws Exception {
    MutableMonitoringRegistry registry = new MutableMonitoringRegistry();
    MonitoringClient client = new StubMonitoringClient();
    registry.registerMonitoringClient(client);
    assertThrows(IllegalStateException.class, () -> registry.registerMonitoringClient(client));
  }

  @Test
  public void testRegisterClearRegisterWorks() throws Exception {
    MutableMonitoringRegistry registry = new MutableMonitoringRegistry();
    MonitoringClient client = new StubMonitoringClient();
    registry.registerMonitoringClient(client);
    assertThat(registry.getMonitoringClient()).isEqualTo(client);

    registry.clear();

    // After clear, we should get the default client.
    assertThat(registry.getMonitoringClient()).isNotInstanceOf(StubMonitoringClient.class);

    // And we can register again.
    registry.registerMonitoringClient(client);
    assertThat(registry.getMonitoringClient()).isEqualTo(client);
  }
}
