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

package com.google.crypto.tink.monitoring;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyFormat;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.internal.LegacyProtoKeyFormat;
import com.google.crypto.tink.internal.ProtoKeyFormatSerialization;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests MonitoringKeysetInfo */
@RunWith(JUnit4.class)
public final class MonitoringKeysetInfoTest {

  KeyFormat makeLegacyProtoKeyFormat(String typeUrl) {
    KeyTemplate template =
        KeyTemplate.newBuilder()
            .setTypeUrl(typeUrl)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setValue(ByteString.EMPTY)
            .build();
    ProtoKeyFormatSerialization serialization = ProtoKeyFormatSerialization.create(template);
    return new LegacyProtoKeyFormat(serialization);
  }

  @Test
  public void addAndGetEntry() throws Exception {
    KeyFormat keyFormat = makeLegacyProtoKeyFormat("typeUrl123");
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoKeyFormat("typeUrl123"))
            .setPrimaryKeyId(123)
            .build();
    assertThat(info.getEntries()).hasSize(1);
    MonitoringKeysetInfo.Entry entry = info.getEntries().get(0);
    assertThat(entry.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(entry.getKeyId()).isEqualTo(123);
    assertThat(entry.getKeyFormat()).isEqualTo(keyFormat);
  }

  @Test
  public void addEntries() throws Exception  {
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoKeyFormat("typeUrl123"))
            .addEntry(KeyStatus.ENABLED, 234, makeLegacyProtoKeyFormat("typeUrl234"))
            .setPrimaryKeyId(123)
            .build();
    assertThat(info.getEntries()).hasSize(2);
  }

  @Test
  public void addSameEntryTwice() throws Exception  {
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoKeyFormat("typeUrl123"))
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoKeyFormat("typeUrl123"))
            .setPrimaryKeyId(123)
            .build();
    // entries are a list, so we can add the same entry twice.
    assertThat(info.getEntries()).hasSize(2);
  }

  @Test
  public void setAndGetAnnotations() throws Exception {
    HashMap<String, String> annotations = new HashMap<>();
    annotations.put("annotation_name1", "annotation_value1");
    annotations.put("annotation_name2", "annotation_value2");
    MonitoringAnnotations monitoringAnnotations =
        MonitoringAnnotations.newBuilder()
            .addAll(annotations)
            .add("annotation_name3", "annotation_value3")
            .add("annotation_name4", "annotation_value4")
            .build();
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .setAnnotations(monitoringAnnotations)
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoKeyFormat("typeUrl123"))
            .setPrimaryKeyId(123)
            .build();
    HashMap<String, String> expected = new HashMap<>();
    expected.put("annotation_name1", "annotation_value1");
    expected.put("annotation_name2", "annotation_value2");
    expected.put("annotation_name3", "annotation_value3");
    expected.put("annotation_name4", "annotation_value4");
    assertThat(info.getAnnotations().toMap()).containsExactlyEntriesIn(expected);
  }

  @Test
  public void primaryKeyMustBeSet() throws Exception  {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            MonitoringKeysetInfo.newBuilder()
                .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoKeyFormat("typeUrl123"))
                .build());
    assertThrows(GeneralSecurityException.class, () -> MonitoringKeysetInfo.newBuilder().build());
  }

  @Test
  public void primaryKeyMustBePresentInEntries() throws Exception  {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            MonitoringKeysetInfo.newBuilder()
                .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoKeyFormat("typeUrl123"))
                .setPrimaryKeyId(124)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            MonitoringKeysetInfo.newBuilder()
                .setPrimaryKeyId(124)
                .build());
  }

  @Test
  public void entriesAreNotModifiable() throws Exception {
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoKeyFormat("typeUrl123"))
            .setPrimaryKeyId(123)
            .setAnnotations(
                MonitoringAnnotations.newBuilder()
                    .add("annotation_name", "annotation_value")
                    .build())
            .build();
    MonitoringKeysetInfo info2 =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(KeyStatus.ENABLED, 234, makeLegacyProtoKeyFormat("typeUrl234"))
            .setPrimaryKeyId(234)
            .build();
    assertThrows(
        UnsupportedOperationException.class,
        () -> info.getAnnotations().toMap().put("name", "value"));
    assertThrows(
        UnsupportedOperationException.class,
        () -> info.getEntries().add(info2.getEntries().get(0)));
  }

  @Test
  public void builderIsInvalidAfterBuild() throws Exception  {
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name2", "annotation_value2").build();
    MonitoringKeysetInfo.Builder builder =
        MonitoringKeysetInfo.newBuilder()
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoKeyFormat("typeUrl123"))
            .setPrimaryKeyId(123)
            .setAnnotations(annotations);
    builder.build();
    assertThrows(IllegalStateException.class, () -> builder.setAnnotations(annotations));
    assertThrows(
        IllegalStateException.class,
        () -> builder.addEntry(KeyStatus.ENABLED, 234, makeLegacyProtoKeyFormat("typeUrl234")));
    assertThrows(IllegalStateException.class, () -> builder.setPrimaryKeyId(123));
  }

  @Test
  public void toStringConversion()  throws Exception {
    MonitoringKeysetInfo info =
        MonitoringKeysetInfo.newBuilder()
            .setAnnotations(
                MonitoringAnnotations.newBuilder()
                    .add("annotation_name1", "annotation_value1")
                    .build())
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoKeyFormat("typeUrl123"))
            .addEntry(KeyStatus.DISABLED, 234, makeLegacyProtoKeyFormat("typeUrl234"))
            .setPrimaryKeyId(123)
            .build();
    assertThat(info.toString())
        .isEqualTo(
            "(annotations={annotation_name1=annotation_value1}, entries=[(status=ENABLED,"
                + " keyId=123, keyFormat='(typeUrl=typeUrl123, outputPrefixType=TINK)'),"
                + " (status=DISABLED, keyId=234, keyFormat='(typeUrl=typeUrl234,"
                + " outputPrefixType=TINK)')], primaryKeyId=123)");
  }

  @Test
  public void equalityTest() throws Exception  {
    MonitoringKeysetInfo info1 =
        MonitoringKeysetInfo.newBuilder()
            .setAnnotations(
                MonitoringAnnotations.newBuilder()
                    .add("annotation_name1", "annotation_value1")
                    .add("annotation_name2", "annotation_value2")
                    .build())
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoKeyFormat("typeUrl123"))
            .addEntry(KeyStatus.ENABLED, 234, makeLegacyProtoKeyFormat("typeUrl234"))
            .setPrimaryKeyId(123)
            .build();
    MonitoringKeysetInfo infoWithAnnotationsInOtherOrder =
        MonitoringKeysetInfo.newBuilder()
            .setAnnotations(
                MonitoringAnnotations.newBuilder()
                    .add("annotation_name2", "annotation_value2")
                    .add("annotation_name1", "annotation_value1")
                    .build())
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoKeyFormat("typeUrl123"))
            .addEntry(KeyStatus.ENABLED, 234, makeLegacyProtoKeyFormat("typeUrl234"))
            .setPrimaryKeyId(123)
            .build();
    MonitoringKeysetInfo infoWithEntriesInOtherOrder =
        MonitoringKeysetInfo.newBuilder()
            .setAnnotations(
                MonitoringAnnotations.newBuilder()
                    .add("annotation_name1", "annotation_value1")
                    .add("annotation_name2", "annotation_value2")
                    .build())
            .addEntry(KeyStatus.ENABLED, 234, makeLegacyProtoKeyFormat("typeUrl234"))
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoKeyFormat("typeUrl123"))
            .setPrimaryKeyId(123)
            .build();
    MonitoringKeysetInfo infoWithOtherAnnotations =
        MonitoringKeysetInfo.newBuilder()
            .setAnnotations(
                MonitoringAnnotations.newBuilder()
                    .add("annotation_name1", "annotation_value1")
                    .add("annotation_name3", "annotation_value3")
                    .build())
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoKeyFormat("typeUrl123"))
            .addEntry(KeyStatus.ENABLED, 234, makeLegacyProtoKeyFormat("typeUrl234"))
            .setPrimaryKeyId(123)
            .build();
    MonitoringKeysetInfo infoWithOtherPrimaryKeyId =
        MonitoringKeysetInfo.newBuilder()
            .setAnnotations(
                MonitoringAnnotations.newBuilder()
                    .add("annotation_name1", "annotation_value1")
                    .add("annotation_name2", "annotation_value2")
                    .build())
            .addEntry(KeyStatus.ENABLED, 123, makeLegacyProtoKeyFormat("typeUrl123"))
            .addEntry(KeyStatus.ENABLED, 234, makeLegacyProtoKeyFormat("typeUrl234"))
            .setPrimaryKeyId(234)
            .build();
    // annotations are a map. They can be added in any order.
    assertThat(info1.equals(infoWithAnnotationsInOtherOrder)).isTrue();
    // Entries are a list. They must be added in the same order for objects to be equal.
    assertThat(info1.equals(infoWithEntriesInOtherOrder)).isFalse();
    assertThat(info1.equals(infoWithOtherAnnotations)).isFalse();
    assertThat(info1.equals(infoWithOtherPrimaryKeyId)).isFalse();
  }
}
