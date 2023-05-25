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
import java.security.GeneralSecurityException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A Mutable version of the {@link PrimitiveRegistry}.
 *
 * <p>This class probably shouldn't exist; it would be better if we had only the
 * PrimitiveRegistry. However, at the moment, we need this, since a call to e.g.
 *
 * <pre> AesCmacKeyManager.register() </pre>
 *
 * should register such an object into a global, mutable registry.
 */
public final class MutablePrimitiveRegistry {
  private static MutablePrimitiveRegistry globalInstance =
      new MutablePrimitiveRegistry();

  public static MutablePrimitiveRegistry globalInstance() {
    return globalInstance;
  }

  public static void resetGlobalInstanceTestOnly() {
    globalInstance = new MutablePrimitiveRegistry();
  }

  private final AtomicReference<PrimitiveRegistry> registry =
      new AtomicReference<>(PrimitiveRegistry.builder().build());

  MutablePrimitiveRegistry() {}

  /**
   * Registers a key primitive constructor for later use in {@link #getPrimitive}.
   *
   * <p>This registers a primitive constructor which can later be used to create a primitive by
   * calling {@link #getPrimitive}. If a constructor for the pair {@code (KeyT, PrimitiveT)} has
   * already been registered and is the same, then the call is ignored; otherwise, an exception is
   * thrown.
   */
  public synchronized <KeyT extends Key, PrimitiveT> void registerPrimitiveConstructor(
      PrimitiveConstructor<KeyT, PrimitiveT> constructor) throws GeneralSecurityException {
    PrimitiveRegistry newRegistry =
        PrimitiveRegistry.builder(registry.get())
            .registerPrimitiveConstructor(constructor)
            .build();
    registry.set(newRegistry);
  }

  public synchronized <InputPrimitiveT, WrapperPrimitiveT> void registerPrimitiveWrapper(
      PrimitiveWrapper<InputPrimitiveT, WrapperPrimitiveT> wrapper)
      throws GeneralSecurityException {
    PrimitiveRegistry newRegistry =
        PrimitiveRegistry.builder(registry.get()).registerPrimitiveWrapper(wrapper).build();
    registry.set(newRegistry);
  }

  /**
   * Creates a primitive from a given key.
   *
   * <p>This will look up a previously registered constructor for the given pair of {@code (KeyT,
   * PrimitiveT)}, and, if successful, use the registered PrimitiveConstructor object to create the
   * requested primitive. Throws if the required constructor has not been registered, or if the
   * primitive construction threw.
   */
  public <KeyT extends Key, PrimitiveT> PrimitiveT getPrimitive(
      KeyT key, Class<PrimitiveT> primitiveClass) throws GeneralSecurityException {
    return registry.get().getPrimitive(key, primitiveClass);
  }

  public <WrapperPrimitiveT> Class<?> getInputPrimitiveClass(
      Class<WrapperPrimitiveT> wrapperClassObject) throws GeneralSecurityException {
    return registry.get().getInputPrimitiveClass(wrapperClassObject);
  }

  public <InputPrimitiveT, WrapperPrimitiveT> WrapperPrimitiveT wrap(
      PrimitiveSet<InputPrimitiveT> primitives, Class<WrapperPrimitiveT> wrapperClassObject)
      throws GeneralSecurityException {
    return registry.get().wrap(primitives, wrapperClassObject);
  }
}
