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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.LegacyProtoParameters;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.monitoring.MonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringKeysetInfo;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ByteString;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class FakeMonitoringClientTest {

  Parameters makeLegacyProtoParameters(String typeUrl) {
    KeyTemplate template =
        KeyTemplate.newBuilder()
            .setTypeUrl(typeUrl)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setValue(ByteString.EMPTY)
            .build();
    ProtoParametersSerialization serialization = ProtoParametersSerialization.create(template);
    return new LegacyProtoParameters(serialization);
  }

  @Test
  public void log() throws Exception {
    FakeMonitoringClient client = new FakeMonitoringClient();
    MonitoringKeysetInfo keysetInfo =
        MonitoringKeysetInfo.newBuilder()
            .setAnnotations(
                MonitoringAnnotations.newBuilder()
                    .add("annotation_name", "annotation_value")
                    .build())
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoParameters("typeUrl123"))
            .addEntry(KeyStatus.ENABLED, 234, makeLegacyProtoParameters("typeUrl234"))
            .setPrimaryKeyId(123)
            .build();
    MonitoringClient.Logger encLogger = client.createLogger(keysetInfo, "aead", "encrypt");

    encLogger.log(123, 42);

    assertThat(client.getLogFailureEntries()).isEmpty();
    List<FakeMonitoringClient.LogEntry> logEntries = client.getLogEntries();
    assertThat(logEntries).hasSize(1);
    FakeMonitoringClient.LogEntry logEntry = logEntries.get(0);
    assertThat(logEntry.getKeysetInfo()).isEqualTo(keysetInfo);
    assertThat(logEntry.getKeyInfo()).isEqualTo(keysetInfo.getEntries().get(0));
    assertThat(logEntry.getPrimitive()).isEqualTo("aead");
    assertThat(logEntry.getApi()).isEqualTo("encrypt");
    assertThat(logEntry.getKeyId()).isEqualTo(123);
    assertThat(logEntry.getNumBytesAsInput()).isEqualTo(42);

    client.clear();
    assertThat(client.getLogEntries()).isEmpty();
  }

  @Test
  public void logFailure() throws Exception {
    FakeMonitoringClient client = new FakeMonitoringClient();
    MonitoringKeysetInfo keysetInfo =
        MonitoringKeysetInfo.newBuilder()
            .setAnnotations(
                MonitoringAnnotations.newBuilder()
                    .add("annotation_name", "annotation_value")
                    .build())
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoParameters("typeUrl123"))
            .addEntry(KeyStatus.ENABLED, 234, makeLegacyProtoParameters("typeUrl234"))
            .setPrimaryKeyId(123)
            .build();
    MonitoringClient.Logger encLogger = client.createLogger(keysetInfo, "aead", "encrypt");

    encLogger.logFailure();

    assertThat(client.getLogEntries()).isEmpty();
    List<FakeMonitoringClient.LogFailureEntry> logFailureEntries = client.getLogFailureEntries();
    assertThat(logFailureEntries).hasSize(1);
    FakeMonitoringClient.LogFailureEntry logFailureEntry = logFailureEntries.get(0);
    assertThat(logFailureEntry.getKeysetInfo()).isEqualTo(keysetInfo);
    assertThat(logFailureEntry.getPrimitive()).isEqualTo("aead");
    assertThat(logFailureEntry.getApi()).isEqualTo("encrypt");

    client.clear();
    assertThat(client.getLogFailureEntries()).isEmpty();
  }

  @Test
  public void twoLoggers() throws Exception {
    FakeMonitoringClient client = new FakeMonitoringClient();
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .setAnnotations(
                MonitoringAnnotations.newBuilder()
                    .add("annotation_name", "annotation_value")
                    .build())
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoParameters("typeUrl123"))
            .addEntry(KeyStatus.ENABLED, 234, makeLegacyProtoParameters("typeUrl234"))
            .setPrimaryKeyId(123)
            .build();
    MonitoringClient.Logger encLogger = client.createLogger(info, "aead", "encrypt");
    MonitoringClient.Logger decLogger = client.createLogger(info, "aead", "decrypt");

    encLogger.log(123, 42);
    decLogger.log(234, 18);
    decLogger.logFailure();

    List<FakeMonitoringClient.LogEntry> logEntries = client.getLogEntries();
    List<FakeMonitoringClient.LogFailureEntry> logFailureEntries = client.getLogFailureEntries();
    assertThat(logEntries).hasSize(2);
    assertThat(logFailureEntries).hasSize(1);
    assertThat(logEntries.get(0).getApi()).isEqualTo("encrypt");
    assertThat(logEntries.get(1).getApi()).isEqualTo("decrypt");
    assertThat(logFailureEntries.get(0).getApi()).isEqualTo("decrypt");
  }


  @Test
  public void logWrongKeyIdFails() throws Exception {
    FakeMonitoringClient client = new FakeMonitoringClient();
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoParameters("typeUrl123"))
            .setPrimaryKeyId(123)
            .build();
    MonitoringClient.Logger encLogger = client.createLogger(info, "aead", "encrypt");

    assertThrows(IllegalStateException.class, () -> encLogger.log(1234, 42));
  }
}
