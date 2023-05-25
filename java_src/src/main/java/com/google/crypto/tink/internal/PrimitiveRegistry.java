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
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
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
  private final Map<Class<?>, PrimitiveWrapper<?, ?>> primitiveWrapperMap;

  /** Allows building PrimitiveRegistry objects. */
  public static final class Builder {
    private final Map<PrimitiveConstructorIndex, PrimitiveConstructor<?, ?>>
        primitiveConstructorMap;
    private final Map<Class<?>, PrimitiveWrapper<?, ?>> primitiveWrapperMap;

    private Builder() {
      primitiveConstructorMap = new HashMap<>();
      primitiveWrapperMap = new HashMap<>();
    }

    private Builder(PrimitiveRegistry registry) {
      primitiveConstructorMap = new HashMap<>(registry.primitiveConstructorMap);
      primitiveWrapperMap = new HashMap<>(registry.primitiveWrapperMap);
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
      if (primitiveConstructor == null) {
        throw new NullPointerException("primitive constructor must be non-null");
      }
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

    @CanIgnoreReturnValue
    public <InputPrimitiveT, WrapperPrimitiveT> Builder registerPrimitiveWrapper(
        PrimitiveWrapper<InputPrimitiveT, WrapperPrimitiveT> wrapper)
        throws GeneralSecurityException {
      if (wrapper == null) {
        throw new NullPointerException("wrapper must be non-null");
      }
      Class<WrapperPrimitiveT> wrapperClassObject = wrapper.getPrimitiveClass();
      if (primitiveWrapperMap.containsKey(wrapperClassObject)) {
        PrimitiveWrapper<?, ?> existingPrimitiveWrapper =
            primitiveWrapperMap.get(wrapperClassObject);
        if (!existingPrimitiveWrapper.equals(wrapper)
            || !wrapper.equals(existingPrimitiveWrapper)) {
          throw new GeneralSecurityException(
              "Attempt to register non-equal PrimitiveWrapper object or input class object for"
                  + " already existing object of type"
                  + wrapperClassObject);
        }
      } else {
        primitiveWrapperMap.put(wrapperClassObject, wrapper);
      }
      return this;
    }

    PrimitiveRegistry build() {
      return new PrimitiveRegistry(this);
    }
  }

  public static Builder builder() {
    return new Builder();
  }

  public static Builder builder(PrimitiveRegistry registry) {
    return new Builder(registry);
  }

  private PrimitiveRegistry(Builder builder) {
    primitiveConstructorMap = new HashMap<>(builder.primitiveConstructorMap);
    primitiveWrapperMap = new HashMap<>(builder.primitiveWrapperMap);
  }

  /**
   * Creates a primitive from a given key.
   *
   * <p>This will look up a previously registered constructor for the given pair of {@code (KeyT,
   * PrimitiveT)}, and, if successful, use the registered PrimitiveConstructor object to create the
   * requested primitive. Throws on a failed lookup, or if the primitive construction threw.
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

  public Class<?> getInputPrimitiveClass(Class<?> wrapperClassObject)
      throws GeneralSecurityException {
    if (!primitiveWrapperMap.containsKey(wrapperClassObject)) {
      throw new GeneralSecurityException(
          "No input primitive class for " + wrapperClassObject + " available");
    }
    return primitiveWrapperMap.get(wrapperClassObject).getInputPrimitiveClass();
  }

  public <InputPrimitiveT, WrapperPrimitiveT> WrapperPrimitiveT wrap(
      PrimitiveSet<InputPrimitiveT> primitives, Class<WrapperPrimitiveT> wrapperClassObject)
      throws GeneralSecurityException {
    if (!primitiveWrapperMap.containsKey(wrapperClassObject)) {
      throw new GeneralSecurityException(
          "No wrapper found for " + wrapperClassObject);
    }
    @SuppressWarnings("unchecked") // We know this is how this map is organized.
    PrimitiveWrapper<?, WrapperPrimitiveT> wrapper =
        (PrimitiveWrapper<?, WrapperPrimitiveT>)
            primitiveWrapperMap.get(wrapperClassObject);
    if (!primitives.getPrimitiveClass().equals(wrapper.getInputPrimitiveClass())
        || !wrapper.getInputPrimitiveClass().equals(primitives.getPrimitiveClass())) {
      throw new GeneralSecurityException(
          "Input primitive type of the wrapper doesn't match the type of primitives in the provided"
              + " PrimitiveSet");
    }
    @SuppressWarnings("unchecked") // The check above ensured this.
    PrimitiveWrapper<InputPrimitiveT, WrapperPrimitiveT> typedWrapper =
        (PrimitiveWrapper<InputPrimitiveT, WrapperPrimitiveT>) wrapper;
    return typedWrapper.wrap(primitives);
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
