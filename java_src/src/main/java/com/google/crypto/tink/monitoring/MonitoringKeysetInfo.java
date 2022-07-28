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

import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.annotations.Alpha;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

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
    private final Parameters parameters;

    public KeyStatus getStatus() {
      return status;
    }

    public int getKeyId() {
      return keyId;
    }

    public Parameters getParameters() {
      return parameters;
    }

    private Entry(KeyStatus status, int keyId, Parameters parameters) {
      this.status = status;
      this.keyId = keyId;
      this.parameters = parameters;
    }

    @Override
    public boolean equals(Object obj) {
      if (!(obj instanceof Entry)) {
        return false;
      }
      Entry entry = (Entry) obj;
      return this.status == entry.status
          && this.keyId == entry.keyId
          && this.parameters.equals(entry.parameters);
    }

    @Override
    public int hashCode() {
      return Objects.hash(status, keyId, parameters.hashCode());
    }

    @Override
    public String toString() {
      return String.format(
          "(status=%s, keyId=%s, parameters='%s')", this.status, this.keyId, this.parameters);
    }
  }

  /** Builder */
  public static final class Builder {
    // builderEntries == null indicates that build has already been called and the builder is not
    // usable anymore.
    @Nullable private ArrayList<Entry> builderEntries = new ArrayList<>();
    private MonitoringAnnotations builderAnnotations = MonitoringAnnotations.EMPTY;
    @Nullable private Integer builderPrimaryKeyId = null;

    public Builder setAnnotations(MonitoringAnnotations annotations) {
      if (builderEntries == null) {
        throw new IllegalStateException("setAnnotations cannot be called after build()");
      }
      builderAnnotations = annotations;
      return this;
    }

    public Builder addEntry(KeyStatus status, int keyId, Parameters parameters) {
      if (builderEntries == null) {
        throw new IllegalStateException("addEntry cannot be called after build()");
      }
      builderEntries.add(new Entry(status, keyId, parameters));
      return this;
    }

    public Builder setPrimaryKeyId(int primaryKeyId) {
      if (builderEntries == null) {
        throw new IllegalStateException("setPrimaryKeyId cannot be called after build()");
      }
      builderPrimaryKeyId = primaryKeyId;
      return this;
    }

    private boolean isKeyIdInEntries(int keyId) {
      for (Entry entry : builderEntries) {
        if (entry.getKeyId() == keyId) {
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
      if (builderPrimaryKeyId != null) {
        // We allow the primary key to not be set. But if it is set, we verify that it is present in
        // the keyset.
        if (!isKeyIdInEntries(builderPrimaryKeyId.intValue())) {
          throw new GeneralSecurityException("primary key ID is not present in entries");
        }
      }
      MonitoringKeysetInfo output =
          new MonitoringKeysetInfo(
              builderAnnotations,
              Collections.unmodifiableList(builderEntries),
              builderPrimaryKeyId);
      // Collections.unmodifiableMap/List only gives an unmodifiable view of the underlying
      // collection. To make output immutable, we have to remove the reference to these collections.
      // This makes the builder unusable.
      builderEntries = null;
      return output;
    }
  }

  private final MonitoringAnnotations annotations;

  @SuppressWarnings("Immutable")
  private final List<Entry> entries;

  @Nullable private final Integer primaryKeyId;

  private MonitoringKeysetInfo(
      MonitoringAnnotations annotations, List<Entry> entries, Integer primaryKeyId) {
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

  @Nullable
  public Integer getPrimaryKeyId() {
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
        && Objects.equals(primaryKeyId, info.primaryKeyId);
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
