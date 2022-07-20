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

import com.google.crypto.tink.annotations.Alpha;
import com.google.errorprone.annotations.Immutable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Immutable keyset annotations used by monitoring.
 *
 * <p>DO NOT USE. This API is not yet ready and may change or be removed.
 */
@Immutable
@Alpha
public final class MonitoringAnnotations {

  public static final MonitoringAnnotations EMPTY = newBuilder().build();

  /** Builder */
  public static final class Builder {
    private HashMap<String, String> builderEntries = new HashMap<>();

    public Builder addAll(Map<String, String> newEntries) {
      if (builderEntries == null) {
        throw new IllegalStateException("addAll cannot be called after build()");
      }
      builderEntries.putAll(newEntries);
      return this;
    }

    public Builder add(String name, String value) {
      if (builderEntries == null) {
        throw new IllegalStateException("add cannot be called after build()");
      }
      builderEntries.put(name, value);
      return this;
    }

    /** Builds the MonitoringAnnotations object. The builder is not usable anymore afterwards. */
    public MonitoringAnnotations build() {
      if (builderEntries == null) {
        throw new IllegalStateException("cannot call build() twice");
      }
      MonitoringAnnotations output =
          new MonitoringAnnotations(Collections.unmodifiableMap(this.builderEntries));
      // Collections.unmodifiableMap only gives an unmodifiable view of the underlying map.
      // To make output immutable, we have to remove the reference to it. This makes the builder
      // unusable afterwards.
      builderEntries = null;
      return output;
    }
  }

  @SuppressWarnings("Immutable")
  private final Map<String, String> entries;

  private MonitoringAnnotations(Map<String, String> entries) {
    this.entries = entries;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  /** Returns an immutable map that contains the annotations. */
  public Map<String, String> toMap() {
    return entries;
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof MonitoringAnnotations)) {
      return false;
    }
    MonitoringAnnotations that = (MonitoringAnnotations) obj;
    return entries.equals(that.entries);
  }

  @Override
  public int hashCode() {
    return entries.hashCode();
  }

  @Override
  public String toString() {
    return entries.toString();
  }
}
