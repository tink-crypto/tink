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

import com.google.crypto.tink.KeyFormat;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.annotations.Alpha;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable representation of a Keyset in a certain point in time for the purpose of monitoring
 * operations involving cryptographic keys.
 *
 * <p>Do not use. This API is not yet ready and may change or be removed.
 */
@Immutable
@Alpha
public final class MonitoringKeysetInfo {

  /** Description about each entry of the Keyset. */
  @Immutable
  public static final class Entry {
    private final KeyStatus status;
    private final int keyId;
    private final KeyFormat keyFormat;

    public KeyStatus getStatus() {
      return status;
    }

    public int getKeyId() {
      return keyId;
    }

    public KeyFormat getKeyFormat() {
      return keyFormat;
    }

    private Entry(KeyStatus status, int keyId, KeyFormat keyFormat) {
      this.status = status;
      this.keyId = keyId;
      this.keyFormat = keyFormat;
    }

    @Override
    public boolean equals(Object obj) {
      if (!(obj instanceof Entry)) {
        return false;
      }
      Entry entry = (Entry) obj;
      return this.status == entry.status
          && this.keyId == entry.keyId
          && this.keyFormat.equals(entry.keyFormat);
    }

    @Override
    public int hashCode() {
      return Objects.hash(status, keyId, keyFormat.hashCode());
    }

    @Override
    public String toString() {
      return String.format(
          "(status=%s, keyId=%s, keyFormat='%s')", this.status, this.keyId, this.keyFormat);
    }
  }

  /** Builder */
  public static final class Builder {
    private ArrayList<Entry> builderEntries = new ArrayList<>();
    private MonitoringAnnotations builderAnnotations = MonitoringAnnotations.EMPTY;
    private Optional<Integer> builderPrimaryKeyId = Optional.empty();

    public Builder setAnnotations(MonitoringAnnotations annotations) {
      if (builderAnnotations == null) {
        throw new IllegalStateException("setAnnotations cannot be called after build()");
      }
      builderAnnotations = annotations;
      return this;
    }

    public Builder addEntry(KeyStatus status, int keyId, KeyFormat keyFormat) {
      if (builderEntries == null) {
        throw new IllegalStateException("addEntry cannot be called after build()");
      }
      builderEntries.add(new Entry(status, keyId, keyFormat));
      return this;
    }

    public Builder setPrimaryKeyId(int primaryKeyId) {
      if (builderPrimaryKeyId == null) {
        throw new IllegalStateException("setPrimaryKeyId cannot be called after build()");
      }
      builderPrimaryKeyId = Optional.of(primaryKeyId);
      return this;
    }

    private boolean isPrimaryKeyIdInEntries() {
      int primary = builderPrimaryKeyId.get();
      for (Entry entry : builderEntries) {
        if (entry.getKeyId() == primary) {
          return true;
        }
      }
      return false;
    }

    /** Builds the MonitoringKeysetInfo object. The builder is not usable anymore afterwards. */
    public MonitoringKeysetInfo build() throws GeneralSecurityException {
      if (builderEntries == null) {
        throw new IllegalStateException("cannot call build() twice");
      }
      if (!builderPrimaryKeyId.isPresent()) {
        throw new GeneralSecurityException("not primary key ID set");
      }
      if (!isPrimaryKeyIdInEntries()) {
        throw new GeneralSecurityException("primary key ID is not present in entries");
      }
      MonitoringKeysetInfo output =
          new MonitoringKeysetInfo(
              builderAnnotations,
              Collections.unmodifiableList(builderEntries),
              builderPrimaryKeyId.get());
      // Collections.unmodifiableMap/List only gives an unmodifiable view of the underlying
      // collection. To make output immutable, we have to remove the reference to these collections.
      // This makes the builder unusable.
      builderEntries = null;
      builderAnnotations = null;
      builderPrimaryKeyId = null;
      return output;
    }
  }

  private final MonitoringAnnotations annotations;

  @SuppressWarnings("Immutable")
  private final List<Entry> entries;

  private final int primaryKeyId;

  private MonitoringKeysetInfo(
      MonitoringAnnotations annotations, List<Entry> entries, int primaryKeyId) {
    this.annotations = annotations;
    this.entries = entries;
    this.primaryKeyId = primaryKeyId;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public MonitoringAnnotations getAnnotations() {
    return annotations;
  }

  public List<Entry> getEntries() {
    return entries;
  }

  public int getPrimaryKeyId() {
    return primaryKeyId;
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof MonitoringKeysetInfo)) {
      return false;
    }
    MonitoringKeysetInfo info = (MonitoringKeysetInfo) obj;
    return annotations.equals(info.annotations)
        && entries.equals(info.entries)
        && (primaryKeyId == info.primaryKeyId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(annotations, entries);
  }

  @Override
  public String toString() {
    return String.format(
        "(annotations=%s, entries=%s, primaryKeyId=%s)", annotations, entries, primaryKeyId);
  }
}
