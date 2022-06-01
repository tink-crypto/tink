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

import com.google.crypto.tink.KeyFormat;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.errorprone.annotations.Immutable;
import java.util.Objects;

/** Implements a KeyFormat for legacy types where no actual KeyFormat is present. */
@Immutable
public final class LegacyProtoKeyFormat extends KeyFormat {
  private final ProtoKeyFormatSerialization serialization;

  /** Creates a new LegacyProtoKeyFormat object. */
  public LegacyProtoKeyFormat(ProtoKeyFormatSerialization serialization) {
    this.serialization = serialization;
  }

  @Override
  public boolean hasIdRequirement() {
    return serialization.getKeyTemplate().getOutputPrefixType() != OutputPrefixType.RAW;
  }

  /** returns the serialization which was used to create this object. */
  public ProtoKeyFormatSerialization getSerialization() {
    return serialization;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof LegacyProtoKeyFormat)) {
      return false;
    }
    ProtoKeyFormatSerialization other = ((LegacyProtoKeyFormat) o).serialization;
    return serialization
            .getKeyTemplate()
            .getOutputPrefixType()
            .equals(other.getKeyTemplate().getOutputPrefixType())
        && serialization.getKeyTemplate().getTypeUrl().equals(other.getKeyTemplate().getTypeUrl())
        && serialization.getKeyTemplate().getValue().equals(other.getKeyTemplate().getValue());
  }

  @Override
  public int hashCode() {
    return Objects.hash(serialization.getKeyTemplate(), serialization.getObjectIdentifier());
  }
}
