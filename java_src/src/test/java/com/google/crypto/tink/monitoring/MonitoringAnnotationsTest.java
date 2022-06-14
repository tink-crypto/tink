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

import java.util.HashMap;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class MonitoringAnnotationsTest {

  @Test
  public void buildToMap() throws Exception {
    HashMap<String, String> mapWithAnnotations = new HashMap<>();
    mapWithAnnotations.put("annotation_name1", "annotation_value1");
    mapWithAnnotations.put("annotation_name2", "annotation_value2");
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder()
            .addAll(mapWithAnnotations)
            .add("annotation_name3", "annotation_value3")
            .add("annotation_name4", "annotation_value4")
            .build();

    HashMap<String, String> expected = new HashMap<>();
    expected.put("annotation_name1", "annotation_value1");
    expected.put("annotation_name2", "annotation_value2");
    expected.put("annotation_name3", "annotation_value3");
    expected.put("annotation_name4", "annotation_value4");
    assertThat(annotations.toMap()).containsExactlyEntriesIn(expected);
  }

  @Test
  public void emptyIsEmpty() throws Exception {
    HashMap<String, String> empty = new HashMap<>();
    assertThat(MonitoringAnnotations.EMPTY.toMap()).containsExactlyEntriesIn(empty);
  }

  @Test
  public void overwriteWithSameName() throws Exception {
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder()
            .add("annotation_name", "old_value")
            .add("annotation_name", "new_value")
            .build();
    HashMap<String, String> expected = new HashMap<>();
    expected.put("annotation_name", "new_value");
    assertThat(annotations.toMap()).containsExactlyEntriesIn(expected);
  }

  @Test
  public void isNotModifiable() throws Exception {
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    assertThrows(
        UnsupportedOperationException.class, () -> annotations.toMap().put("name", "value"));
  }

  @Test
  public void builderIsInvalidAfterBuild() throws Exception {
    MonitoringAnnotations.Builder builder =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value");
    builder.build();
    assertThrows(
        IllegalStateException.class, () -> builder.add("annotation_name2", "annotation_value2"));
    HashMap<String, String> newAnnotations = new HashMap<>();
    newAnnotations.put("annotation_name", "new_value");
    assertThrows(IllegalStateException.class, () -> builder.addAll(newAnnotations));
    assertThrows(IllegalStateException.class, builder::build);
  }

  @Test
  public void toStringConversion() throws Exception {
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name1", "annotation_value1").build();
    assertThat(annotations.toString()).isEqualTo("{annotation_name1=annotation_value1}");
  }

  @Test
  public void equalityTest() throws Exception {
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder()
            .add("annotation_name1", "annotation_value1")
            .add("annotation_name2", "annotation_value2")
            .build();
    MonitoringAnnotations annotationsInOtherOrder =
        MonitoringAnnotations.newBuilder()
            .add("annotation_name2", "annotation_value2")
            .add("annotation_name1", "annotation_value1")
            .build();
    MonitoringAnnotations otherAnnotations =
        MonitoringAnnotations.newBuilder()
            .add("annotation_name1", "annotation_value1")
            .add("annotation_name3", "annotation_value3")
            .build();
    // annotations are a map. They can be added in any order.
    assertThat(annotations.equals(annotationsInOtherOrder)).isTrue();
    assertThat(annotations.equals(otherAnnotations)).isFalse();
  }
}
