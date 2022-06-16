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

import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.monitoring.MonitoringKeysetInfo;
import com.google.crypto.tink.proto.KeyStatusType;
import java.security.GeneralSecurityException;
import java.util.List;
import javax.annotation.Nullable;

/** Some util functions needed to add monitoring to the Primitives. */
public final class MonitoringUtil {

  private static KeyStatus parseStatus(KeyStatusType in) {
    switch (in) {
      case ENABLED:
        return KeyStatus.ENABLED;
      case DISABLED:
        return KeyStatus.DISABLED;
      case DESTROYED:
        return KeyStatus.DESTROYED;
      default:
        throw new IllegalStateException("Unknown key status");
    }
  }

  public static <P> MonitoringKeysetInfo getMonitoringKeysetInfo(PrimitiveSet<P> primitiveSet) {
    MonitoringKeysetInfo.Builder builder = MonitoringKeysetInfo.newBuilder();
    builder.setAnnotations(primitiveSet.getAnnotations());
    for (List<PrimitiveSet.Entry<P>> entries : primitiveSet.getAll()) {
      for (PrimitiveSet.Entry<P> entry : entries) {
        builder.addEntry(parseStatus(entry.getStatus()), entry.getKeyId(), entry.getKeyFormat());
      }
    }
    @Nullable PrimitiveSet.Entry<P> primary = primitiveSet.getPrimary();
    if (primary != null) {
      builder.setPrimaryKeyId(primitiveSet.getPrimary().getKeyId());
    }
    try {
      return builder.build();
    } catch (GeneralSecurityException e) {
      // This shouldn't happen, since for PrimitiveSets, the primary's key id is always in the
      // entries list.
      throw new IllegalStateException(e);
    }
  }

  private MonitoringUtil() {}
}
