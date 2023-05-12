// Copyright 2023 Google LLC
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

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/** Utility class for bidirectional conversion to and from proto enum types. */
@Immutable
public final class EnumTypeProtoConverter<E extends Enum<E>, O> {

  /** {@code fromProtoEnumMap} built from {@link java.util.Collections#unmodifiableMap}. */
  @SuppressWarnings("Immutable")
  private final Map<E, O> fromProtoEnumMap;

  /** {@code toProtoEnumMap} built from {@link java.util.Collections#unmodifiableMap}. */
  @SuppressWarnings("Immutable")
  private final Map<O, E> toProtoEnumMap;

  private EnumTypeProtoConverter(Map<E, O> fromProtoEnumMap, Map<O, E> toProtoEnumMap) {
    this.fromProtoEnumMap = fromProtoEnumMap;
    this.toProtoEnumMap = toProtoEnumMap;
  }

  /** Builds instances of {@link EnumTypeProtoConverter}. */
  public static final class Builder<E extends Enum<E>, O> {
    Map<E, O> fromProtoEnumMap = new HashMap<>();
    Map<O, E> toProtoEnumMap = new HashMap<>();

    private Builder() {}

    /** Adds bidirectional conversion mapping between {@code protoEnum} and {@code objectEnum}. */
    @CanIgnoreReturnValue
    public Builder<E, O> add(E protoEnum, O objectEnum) {
      fromProtoEnumMap.put(protoEnum, objectEnum);
      toProtoEnumMap.put(objectEnum, protoEnum);
      return this;
    }

    public EnumTypeProtoConverter<E, O> build() {
      return new EnumTypeProtoConverter<>(
          Collections.unmodifiableMap(fromProtoEnumMap),
          Collections.unmodifiableMap(toProtoEnumMap));
    }
  }

  public static <E extends Enum<E>, O> Builder<E, O> builder() {
    return new Builder<>();
  }

  /** Converts {@code objectEnum} to the equivalent proto enum. */
  public E toProtoEnum(O objectEnum) throws GeneralSecurityException {
    E protoEnum = toProtoEnumMap.get(objectEnum);
    if (protoEnum == null) {
      throw new GeneralSecurityException("Unable to convert object enum: " + objectEnum);
    }
    return protoEnum;
  }

  /** Converts {@code protoEnum} to the equivalent object enum. */
  public O fromProtoEnum(E protoEnum) throws GeneralSecurityException {
    O objectEnum = fromProtoEnumMap.get(protoEnum);
    if (objectEnum == null) {
      throw new GeneralSecurityException("Unable to convert proto enum: " + protoEnum);
    }
    return objectEnum;
  }
}
