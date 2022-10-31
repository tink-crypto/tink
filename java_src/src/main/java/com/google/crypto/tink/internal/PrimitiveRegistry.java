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

import com.google.crypto.tink.Key;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Allows registering {@code PrimitiveConstructor} objects, and creating primitives with those
 * objects.
 */
public class PrimitiveRegistry {
  private final Map<PrimitiveConstructorIndex, PrimitiveConstructor<?, ?>> primitiveConstructorMap;

  /** Allows building PrimitiveRegistry objects. */
  public static final class Builder {
    private final Map<PrimitiveConstructorIndex, PrimitiveConstructor<?, ?>>
        primitiveConstructorMap;

    public Builder() {
      primitiveConstructorMap = new HashMap<>();
    }

    public Builder(PrimitiveRegistry registry) {
      primitiveConstructorMap = new HashMap<>(registry.primitiveConstructorMap);
    }

    /**
     * Registers a primitive constructor for later use in {@link #getPrimitive}.
     *
     * <p>This registers a primitive constructor which can later be used to create a primitive
     * by calling {@link #getPrimitive}. If a constructor for the pair {@code (KeyT, PrimitiveT)}
     * has already been registered, this checks if they are the same. If they are, the call is
     * ignored, otherwise an exception is thrown.
     */
    @CanIgnoreReturnValue
    public <KeyT extends Key, PrimitiveT> Builder registerPrimitiveConstructor(
        PrimitiveConstructor<KeyT, PrimitiveT> primitiveConstructor)
        throws GeneralSecurityException {
      PrimitiveConstructorIndex index =
          new PrimitiveConstructorIndex(
              primitiveConstructor.getKeyClass(), primitiveConstructor.getPrimitiveClass());
      if (primitiveConstructorMap.containsKey(index)) {
        PrimitiveConstructor<?, ?> existingConstructor = primitiveConstructorMap.get(index);
        if (!existingConstructor.equals(primitiveConstructor)
            || !primitiveConstructor.equals(existingConstructor)) {
          throw new GeneralSecurityException(
              "Attempt to register non-equal PrimitiveConstructor object for already existing"
                  + " object of type: "
                  + index);
        }
      } else {
        primitiveConstructorMap.put(index, primitiveConstructor);
      }
      return this;
    }

    PrimitiveRegistry build() {
      return new PrimitiveRegistry(this);
    }
  }

  private PrimitiveRegistry(Builder builder) {
    primitiveConstructorMap = new HashMap<>(builder.primitiveConstructorMap);
  }

  /**
   * Creates a primitive from a given key.
   *
   * <p>This will look up a previously registered constructor for the given pair of
   * {@code (KeyT, PrimitiveT)}, and, if successful, use the registered PrimitiveConstructor object
   * to create the requested primitive. Throws on a failed lookup, or if the primitive construction
   * threw.
   */
  public <KeyT extends Key, PrimitiveT> PrimitiveT getPrimitive(
      KeyT key, Class<PrimitiveT> primitiveClass) throws GeneralSecurityException {
    PrimitiveConstructorIndex index = new PrimitiveConstructorIndex(key.getClass(), primitiveClass);
    if (!primitiveConstructorMap.containsKey(index)) {
      throw new GeneralSecurityException("No PrimitiveConstructor for " + index + " available");
    }
    @SuppressWarnings("unchecked") // We know we only insert like this.
    PrimitiveConstructor<KeyT, PrimitiveT> primitiveConstructor =
        (PrimitiveConstructor<KeyT, PrimitiveT>) primitiveConstructorMap.get(index);
    return primitiveConstructor.constructPrimitive(key);
  }

  private static final class PrimitiveConstructorIndex {
    private final Class<?> keyClass;
    private final Class<?> primitiveClass;

    private PrimitiveConstructorIndex(Class<?> keyClass, Class<?> primitiveClass) {
      this.keyClass = keyClass;
      this.primitiveClass = primitiveClass;
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof PrimitiveConstructorIndex)) {
        return false;
      }
      PrimitiveConstructorIndex other = (PrimitiveConstructorIndex) o;
      return other.keyClass.equals(keyClass) && other.primitiveClass.equals(primitiveClass);
    }

    @Override
    public int hashCode() {
      return Objects.hash(keyClass, primitiveClass);
    }

    @Override
    public String toString() {
      return keyClass.getSimpleName() + " with primitive type: " + primitiveClass.getSimpleName();
    }
  }
}
