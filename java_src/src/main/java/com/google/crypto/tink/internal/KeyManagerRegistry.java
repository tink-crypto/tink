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

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import java.security.GeneralSecurityException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Logger;

/**
 * An internal API to register KeyManagers.
 *
 * <p>The KeyManagerRegistry provides an API to register KeyManagers, ensuring FIPS
 * compatibility. For registered managers, it gives access to the following operations:
 *
 * <ul>
 *   <li>Retrive KeyManagers
 * </ul>
 */
public final class KeyManagerRegistry {
  private static final Logger logger = Logger.getLogger(KeyManagerRegistry.class.getName());

  // A map from the TypeUrl to the KeyManager.
  private ConcurrentMap<String, KeyManager<?>> keyManagerMap;
  // typeUrl -> newKeyAllowed mapping
  private ConcurrentMap<String, Boolean> newKeyAllowedMap;

  private static final KeyManagerRegistry GLOBAL_INSTANCE = new KeyManagerRegistry();

  /** Returns the global instance. */
  public static KeyManagerRegistry globalInstance() {
    return GLOBAL_INSTANCE;
  }

  /** Resets the global instance. Should only be used in tests. Not thread safe. */
  public static void resetGlobalInstanceTestOnly() {
    GLOBAL_INSTANCE.keyManagerMap = new ConcurrentHashMap<>();
    GLOBAL_INSTANCE.newKeyAllowedMap = new ConcurrentHashMap<>();
  }

  public KeyManagerRegistry(KeyManagerRegistry original) {
    keyManagerMap = new ConcurrentHashMap<>(original.keyManagerMap);
    newKeyAllowedMap = new ConcurrentHashMap<>(original.newKeyAllowedMap);
  }

  public KeyManagerRegistry() {
    keyManagerMap = new ConcurrentHashMap<>();
    newKeyAllowedMap = new ConcurrentHashMap<>();
  }

  private synchronized KeyManager<?> getKeyManagerOrThrow(String typeUrl)
      throws GeneralSecurityException {
    if (!keyManagerMap.containsKey(typeUrl)) {
      throw new GeneralSecurityException("No key manager found for key type " + typeUrl);
    }
    return keyManagerMap.get(typeUrl);
  }

  private synchronized void insertKeyManager(
      final KeyManager<?> manager, boolean forceOverwrite, boolean newKeyAllowed)
      throws GeneralSecurityException {
    String typeUrl = manager.getKeyType();
    if (newKeyAllowed && newKeyAllowedMap.containsKey(typeUrl) && !newKeyAllowedMap.get(typeUrl)) {
      throw new GeneralSecurityException("New keys are already disallowed for key type " + typeUrl);
    }
    KeyManager<?> existing = keyManagerMap.get(typeUrl);
    if (existing != null && !existing.getClass().equals(manager.getClass())) {
      logger.warning("Attempted overwrite of a registered key manager for key type " + typeUrl);
      throw new GeneralSecurityException(
          String.format(
              "typeUrl (%s) is already registered with %s, cannot be re-registered with %s",
              typeUrl, existing.getClass().getName(), manager.getClass().getName()));
    }
    if (!forceOverwrite) {
      keyManagerMap.putIfAbsent(typeUrl, manager);
    } else {
      keyManagerMap.put(typeUrl, manager);
    }
    newKeyAllowedMap.put(typeUrl, newKeyAllowed);
  }

  /** Attempts to insert the given KeyManager into the object. */
  public synchronized <P> void registerKeyManager(
      final KeyManager<P> manager, boolean newKeyAllowed) throws GeneralSecurityException {
    registerKeyManagerWithFipsCompatibility(
        manager, TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS, newKeyAllowed);
  }

  /**
   * Attempts to insert the given KeyManager into the object; the caller guarantees that the given
   * key manager satisfies the given FIPS compatibility.
   */
  public synchronized <P> void registerKeyManagerWithFipsCompatibility(
      final KeyManager<P> manager,
      TinkFipsUtil.AlgorithmFipsCompatibility compatibility,
      boolean newKeyAllowed)
      throws GeneralSecurityException {
    if (!compatibility.isCompatible()) {
      throw new GeneralSecurityException(
          "Cannot register key manager: FIPS compatibility insufficient");
    }
    insertKeyManager(manager, /* forceOverwrite= */ false, newKeyAllowed);
  }

  public boolean typeUrlExists(String typeUrl) {
    return keyManagerMap.containsKey(typeUrl);
  }

  /**
   * @return a {@link KeyManager} for the given {@code typeUrl} and {@code primitiveClass}(if found
   *     and this key type supports this primitive).
   */
  @SuppressWarnings("unchecked") // We just checked equality above the cast.
  public <P> KeyManager<P> getKeyManager(String typeUrl, Class<P> primitiveClass)
      throws GeneralSecurityException {
    KeyManager<?> manager = getKeyManagerOrThrow(typeUrl);
    if (manager.getPrimitiveClass().equals(primitiveClass)) {
      return (KeyManager<P>) manager;
    }
    throw new GeneralSecurityException(
        "Primitive type "
            + primitiveClass.getName()
            + " not supported by key manager of type "
            + manager.getClass()
            + ", which only supports: "
            + manager.getPrimitiveClass());
  }

  /**
   * @return a {@link KeyManager} for the given {@code typeUrl} (if found).
   */
  public KeyManager<?> getUntypedKeyManager(String typeUrl) throws GeneralSecurityException {
    return getKeyManagerOrThrow(typeUrl);
  }

  public boolean isNewKeyAllowed(String typeUrl) {
    return newKeyAllowedMap.get(typeUrl);
  }

  public boolean isEmpty() {
    return keyManagerMap.isEmpty();
  }

  /**
   * Restricts Tink to FIPS if this is the global instance.
   *
   * <p>We make this a member method (instead of a static one which gets the global instance)
   * because the call to "useOnlyFips" needs to happen under the same mutex lock which protects the
   * registerKeyManager methods.
   */
  public synchronized void restrictToFipsIfEmptyAndGlobalInstance()
      throws GeneralSecurityException {
    if (this != globalInstance()) {
      throw new GeneralSecurityException("Only the global instance can be restricted to FIPS.");
    }
    // If we are already using FIPS mode, do nothing.
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }

    if (!isEmpty()) {
      throw new GeneralSecurityException("Could not enable FIPS mode as Registry is not empty.");
    }
    TinkFipsUtil.setFipsRestricted();
  }
}
