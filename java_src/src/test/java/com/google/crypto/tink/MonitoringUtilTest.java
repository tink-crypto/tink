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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.monitoring.MonitoringKeysetInfo;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.testing.TestUtil;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class MonitoringUtilTest {

  private static final byte[] KEY = TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f");
  private static final byte[] KEY2 = TestUtil.hexDecode("100102030405060708090a0b0c0d0e0f");

  @Test
  public void monitoringKeysetInfoFromPrimitiveSet() throws Exception {
    Keyset.Key key =
        TestUtil.createKey(
            TestUtil.createAesGcmKeyData(KEY), 42, KeyStatusType.ENABLED, OutputPrefixType.TINK);
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    PrimitiveSet<Aead> primitives =
        PrimitiveSet.newBuilder(Aead.class)
            .setAnnotations(annotations)
            .addPrimaryPrimitive(Registry.getPrimitive(key.getKeyData(), Aead.class), key)
            .build();
    MonitoringKeysetInfo keysetInfo = MonitoringUtil.getMonitoringKeysetInfo(primitives);
    assertThat(keysetInfo.getAnnotations()).isEqualTo(annotations);
    assertThat(keysetInfo.getPrimaryKeyId()).isEqualTo(42);
    List<MonitoringKeysetInfo.Entry> entries = keysetInfo.getEntries();
    assertThat(entries).hasSize(1);
    assertThat(entries.get(0).getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(entries.get(0).getKeyId()).isEqualTo(42);
    assertThat(entries.get(0).getKeyFormat().toString())
        .isEqualTo(
            "(typeUrl=type.googleapis.com/google.crypto.tink.AesGcmKey, outputPrefixType=TINK)");
  }

  @Test
  public void monitoringKeysetInfoFromPrimitiveSetTwoEntries() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createAesGcmKeyData(KEY), 42, KeyStatusType.ENABLED, OutputPrefixType.TINK);
    Keyset.Key key2 =
        TestUtil.createKey(
            TestUtil.createAesGcmKeyData(KEY2), 43, KeyStatusType.ENABLED, OutputPrefixType.RAW);
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    PrimitiveSet<Aead> primitives =
        PrimitiveSet.newBuilder(Aead.class)
            .setAnnotations(annotations)
            .addPrimaryPrimitive(Registry.getPrimitive(key1.getKeyData(), Aead.class), key1)
            .addPrimitive(Registry.getPrimitive(key2.getKeyData(), Aead.class), key2)
            .build();
    MonitoringKeysetInfo keysetInfo = MonitoringUtil.getMonitoringKeysetInfo(primitives);
    assertThat(keysetInfo.getEntries()).hasSize(2);
  }

  @Test
  public void monitoringKeysetInfoFromPrimitiveSetWithoutPrimaryAndAnnotations() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createAesGcmKeyData(KEY), 42, KeyStatusType.ENABLED, OutputPrefixType.TINK);
    PrimitiveSet<Aead> primitives =
        PrimitiveSet.newBuilder(Aead.class)
            .addPrimitive(Registry.getPrimitive(key1.getKeyData(), Aead.class), key1)
            .build();
    MonitoringKeysetInfo keysetInfo = MonitoringUtil.getMonitoringKeysetInfo(primitives);
    assertThat(keysetInfo.getPrimaryKeyId()).isNull();
    assertThat(keysetInfo.getAnnotations().toMap()).isEmpty();
  }

  @Test
  public void doNothingLoggerWorks() throws Exception {
    // We only test that calling the function doesn't throw any exceptions.
    MonitoringUtil.DO_NOTHING_LOGGER.log(42, 1234);
    MonitoringUtil.DO_NOTHING_LOGGER.logFailure();
  }
}
