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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.testing.TestUtil.assertExceptionContains;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.proto.Keyset;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for CleartextKeysetHandle. */
@RunWith(JUnit4.class)
public class CleartextKeysetHandleTest {
  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    TinkConfig.register();
  }

  @Test
  public void testParse() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = KeyTemplates.get("HMAC_SHA256_128BITTAG");
    KeysetHandle handle = KeysetHandle.generateNew(template);
    Keyset keyset = CleartextKeysetHandle.getKeyset(handle);
    handle = CleartextKeysetHandle.parseFrom(keyset.toByteArray());
    assertEquals(keyset, handle.getKeyset());
    handle.getPrimitive(Mac.class);
  }

  @Test
  public void testRead() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = KeyTemplates.get("HMAC_SHA256_128BITTAG");
    KeysetHandle handle = KeysetHandle.generateNew(template);
    Keyset keyset1 = handle.getKeyset();

    KeysetHandle handle1 =
        CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(keyset1.toByteArray()));
    assertEquals(keyset1, handle1.getKeyset());

    KeysetHandle handle2 = KeysetHandle.generateNew(template);
    Keyset keyset2 = handle2.getKeyset();
    assertEquals(1, keyset2.getKeyCount());
    Keyset.Key key2 = keyset2.getKey(0);
    assertEquals(keyset2.getPrimaryKeyId(), key2.getKeyId());
    assertEquals(template.getTypeUrl(), key2.getKeyData().getTypeUrl());
    Mac unused = handle2.getPrimitive(Mac.class);
  }

  @Test
  public void testWriteRead_samePrimitive() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("HMAC_SHA256_128BITTAG"));

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    CleartextKeysetHandle.write(handle, writer);
    byte[] serializedKeyset = outputStream.toByteArray();

    ByteArrayInputStream inputStream1 = new ByteArrayInputStream(serializedKeyset);
    KeysetReader reader1 = BinaryKeysetReader.withInputStream(inputStream1);
    KeysetHandle readHandle1 = CleartextKeysetHandle.read(reader1);

    ByteArrayInputStream inputStream2 = new ByteArrayInputStream(serializedKeyset);
    KeysetReader reader2 = BinaryKeysetReader.withInputStream(inputStream2);
    KeysetHandle readHandle2 = CleartextKeysetHandle.read(reader2, new HashMap<String, String>());

    // Check that the handle returned by CleartextKeysetHandle.read generates the same MAC.
    Mac mac = handle.getPrimitive(Mac.class);
    Mac readMac1 = readHandle1.getPrimitive(Mac.class);
    Mac readMac2 = readHandle2.getPrimitive(Mac.class);
    byte[] data = "data".getBytes(UTF_8);
    assertThat(readMac1.computeMac(data)).isEqualTo(mac.computeMac(data));
    assertThat(readMac2.computeMac(data)).isEqualTo(mac.computeMac(data));
  }

  @Test
  public void testReadInvalidKeyset() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = KeyTemplates.get("HMAC_SHA256_128BITTAG");
    Keyset keyset = KeysetHandle.generateNew(template).getKeyset();

    byte[] proto = keyset.toByteArray();
    proto[0] = (byte) ~proto[0];
    assertThrows(
        IOException.class,
        () -> {
          KeysetHandle unused = CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(proto));
        });
    assertThrows(
        IOException.class,
        () -> {
          KeysetHandle unused =
              CleartextKeysetHandle.read(
                  BinaryKeysetReader.withBytes(proto), new HashMap<String, String>());
        });
  }

  @Test
  public void testVoidInputs() throws Exception {
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(new byte[0])));
    assertExceptionContains(e, "empty keyset");

    GeneralSecurityException e2 =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                CleartextKeysetHandle.read(
                    BinaryKeysetReader.withBytes(new byte[0]), new HashMap<String, String>()));
    assertExceptionContains(e2, "empty keyset");

    GeneralSecurityException e3 =
        assertThrows(
            GeneralSecurityException.class, () -> CleartextKeysetHandle.parseFrom(new byte[0]));
    assertExceptionContains(e3, "empty keyset");
  }

  @Test
  public void testReadWithAnnotations_getLoggedByMonitoringClient() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    // Generate a serialized keyset
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(
        KeysetHandle.generateNew(KeyTemplates.get("HMAC_SHA256_128BITTAG")),
        BinaryKeysetWriter.withOutputStream(outputStream));
    byte[] serializedKeyset = outputStream.toByteArray();

    Map<String, String> annotations = new HashMap<>();
    annotations.put("annotation_name", "annotation_value");
    KeysetHandle handle =
        CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(serializedKeyset), annotations);

    // Trigger monitoring event and verify that it gets logged with the annotations are set.
    Mac mac = handle.getPrimitive(Mac.class);
    byte[] unused = mac.computeMac("data".getBytes(UTF_8));

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(1);
    FakeMonitoringClient.LogEntry entry = logEntries.get(0);
    MonitoringAnnotations expectedAnnotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    assertThat(entry.getKeysetInfo().getAnnotations()).isEqualTo(expectedAnnotations);
  }
}
