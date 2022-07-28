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

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.errorprone.annotations.Immutable;
import java.util.Objects;

/** Implements a Parameters object for legacy types where no actual Parameters object is present. */
@Immutable
public final class LegacyProtoParameters extends Parameters {
  private final ProtoParametersSerialization serialization;

  /** Creates a new LegacyProtoParameters object. */
  public LegacyProtoParameters(ProtoParametersSerialization serialization) {
    this.serialization = serialization;
  }

  @Override
  public boolean hasIdRequirement() {
    return serialization.getKeyTemplate().getOutputPrefixType() != OutputPrefixType.RAW;
  }

  /** returns the serialization which was used to create this object. */
  public ProtoParametersSerialization getSerialization() {
    return serialization;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof LegacyProtoParameters)) {
      return false;
    }
    ProtoParametersSerialization other = ((LegacyProtoParameters) o).serialization;
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

  // This function is needed because LiteProto do not have a good toString function.
  private static String outputPrefixToString(OutputPrefixType outputPrefixType) {
    switch (outputPrefixType) {
      case TINK:
        return "TINK";
      case LEGACY:
        return "LEGACY";
      case RAW:
        return "RAW";
      case CRUNCHY:
        return "CRUNCHY";
      default:
        return "UNKNOWN";
    }
  }

  @Override
  public String toString() {
    return String.format(
        "(typeUrl=%s, outputPrefixType=%s)",
        serialization.getKeyTemplate().getTypeUrl(),
        outputPrefixToString(serialization.getKeyTemplate().getOutputPrefixType()));
  }
}
