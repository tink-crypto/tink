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

package com.google.crypto.tink;

import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.PrivateKeyTypeManager;
import com.google.crypto.tink.proto.KeyData;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Logger;

/**
 * An internal API to register KeyManagers and KeyTypeManagers.
 *
 * <p>The KeyManagerRegistry provides an API to register Key(Type)Managers, ensuring FIPS
 * compatibility. For registered managers, it gives access to the following operations:
 *
 * <ul>
 *   <li>Retrive KeyManagers (but not KeyTypeManagers)
 *   <li>Parsing keys (only if KeyTypeManagers have been registered)
 * </ul>
 */
final class KeyManagerRegistry {
  private static final Logger logger = Logger.getLogger(KeyManagerRegistry.class.getName());

  // A map from the TypeUrl to the KeyManagerContainer.
  private final ConcurrentMap<String, KeyManagerContainer> keyManagerMap;

  KeyManagerRegistry(KeyManagerRegistry original) {
    keyManagerMap = new ConcurrentHashMap<>(original.keyManagerMap);
  }

  KeyManagerRegistry() {
    keyManagerMap = new ConcurrentHashMap<>();
  }

  /**
   * A container which either is constructed from a {@link KeyTypeManager} or from a {@link
   * KeyManager}.
   */
  private static interface KeyManagerContainer {
    /**
     * Returns the KeyManager for the given primitive or throws if the given primitive is not in
     * supportedPrimitives.
     */
    <P> KeyManager<P> getKeyManager(Class<P> primitiveClass) throws GeneralSecurityException;

    /**
     * Returns a KeyManager from the given container. If a KeyTypeManager has been provided, creates
     * a KeyManager for some primitive.
     */
    KeyManager<?> getUntypedKeyManager();

    /**
     * The Class object corresponding to the actual KeyTypeManager/KeyManager used to build this
     * object.
     */
    Class<?> getImplementingClass();

    /**
     * The primitives supported by the underlying {@link KeyTypeManager} resp. {@link KeyManager}.
     */
    Set<Class<?>> supportedPrimitives();

    /**
     * The Class object corresponding to the public key manager when this key manager was registered
     * as first argument with "registerAsymmetricKeyManagers". Null otherwise.
     */
    Class<?> publicKeyManagerClassOrNull();

    /**
     * Parses a key into a corresponding message lite. Only works if the key type has been
     * registered with a KeyTypeManager, returns null otherwise.
     *
     * <p>Can throw exceptions if validation fails or if parsing fails.
     */
    MessageLite parseKey(ByteString serializedKey)
        throws GeneralSecurityException, InvalidProtocolBufferException;
  }

  private static <P> KeyManagerContainer createContainerFor(KeyManager<P> keyManager) {
    final KeyManager<P> localKeyManager = keyManager;
    return new KeyManagerContainer() {
      @Override
      public <Q> KeyManager<Q> getKeyManager(Class<Q> primitiveClass)
          throws GeneralSecurityException {
        if (!localKeyManager.getPrimitiveClass().equals(primitiveClass)) {
          throw new InternalError(
              "This should never be called, as we always first check supportedPrimitives.");
        }
        @SuppressWarnings("unchecked") // We checked equality of the primitiveClass objects.
        KeyManager<Q> result = (KeyManager<Q>) localKeyManager;
        return result;
      }

      @Override
      public KeyManager<?> getUntypedKeyManager() {
        return localKeyManager;
      }

      @Override
      public Class<?> getImplementingClass() {
        return localKeyManager.getClass();
      }

      @Override
      public Set<Class<?>> supportedPrimitives() {
        return Collections.<Class<?>>singleton(localKeyManager.getPrimitiveClass());
      }

      @Override
      public Class<?> publicKeyManagerClassOrNull() {
        return null;
      }

      @Override
      public MessageLite parseKey(ByteString serializedKey)
          throws GeneralSecurityException, InvalidProtocolBufferException {
        return null;
      }
    };
  }

  private static <KeyProtoT extends MessageLite> KeyManagerContainer createContainerFor(
      KeyTypeManager<KeyProtoT> keyManager) {
    final KeyTypeManager<KeyProtoT> localKeyManager = keyManager;
    return new KeyManagerContainer() {
      @Override
      public <Q> KeyManager<Q> getKeyManager(Class<Q> primitiveClass)
          throws GeneralSecurityException {
        try {
          return new KeyManagerImpl<>(localKeyManager, primitiveClass);
        } catch (IllegalArgumentException e) {
          throw new GeneralSecurityException("Primitive type not supported", e);
        }
      }

      @Override
      public KeyManager<?> getUntypedKeyManager() {
        return new KeyManagerImpl<>(
            localKeyManager, localKeyManager.firstSupportedPrimitiveClass());
      }

      @Override
      public Class<?> getImplementingClass() {
        return localKeyManager.getClass();
      }

      @Override
      public Set<Class<?>> supportedPrimitives() {
        return localKeyManager.supportedPrimitives();
      }

      @Override
      public Class<?> publicKeyManagerClassOrNull() {
        return null;
      }

      @Override
      public MessageLite parseKey(ByteString serializedKey)
          throws GeneralSecurityException, InvalidProtocolBufferException {
        KeyProtoT result = localKeyManager.parseKey(serializedKey);
        localKeyManager.validateKey(result);
        return result;
      }
    };
  }

  private static <KeyProtoT extends MessageLite, PublicKeyProtoT extends MessageLite>
      KeyManagerContainer createPrivateKeyContainerFor(
          final PrivateKeyTypeManager<KeyProtoT, PublicKeyProtoT> privateKeyTypeManager,
          final KeyTypeManager<PublicKeyProtoT> publicKeyTypeManager) {
    final PrivateKeyTypeManager<KeyProtoT, PublicKeyProtoT> localPrivateKeyManager =
        privateKeyTypeManager;
    final KeyTypeManager<PublicKeyProtoT> localPublicKeyManager = publicKeyTypeManager;
    return new KeyManagerContainer() {
      @Override
      public <Q> KeyManager<Q> getKeyManager(Class<Q> primitiveClass)
          throws GeneralSecurityException {
        try {
          return new PrivateKeyManagerImpl<>(
              localPrivateKeyManager, localPublicKeyManager, primitiveClass);
        } catch (IllegalArgumentException e) {
          throw new GeneralSecurityException("Primitive type not supported", e);
        }
      }

      @Override
      public KeyManager<?> getUntypedKeyManager() {
        return new PrivateKeyManagerImpl<>(
            localPrivateKeyManager,
            localPublicKeyManager,
            localPrivateKeyManager.firstSupportedPrimitiveClass());
      }

      @Override
      public Class<?> getImplementingClass() {
        return localPrivateKeyManager.getClass();
      }

      @Override
      public Set<Class<?>> supportedPrimitives() {
        return localPrivateKeyManager.supportedPrimitives();
      }

      @Override
      public Class<?> publicKeyManagerClassOrNull() {
        return localPublicKeyManager.getClass();
      }

      @Override
      public MessageLite parseKey(ByteString serializedKey)
          throws GeneralSecurityException, InvalidProtocolBufferException {
        KeyProtoT result = localPrivateKeyManager.parseKey(serializedKey);
        localPrivateKeyManager.validateKey(result);
        return result;
      }
    };
  }

  private synchronized KeyManagerContainer getKeyManagerContainerOrThrow(String typeUrl)
      throws GeneralSecurityException {
    if (!keyManagerMap.containsKey(typeUrl)) {
      throw new GeneralSecurityException("No key manager found for key type " + typeUrl);
    }
    return keyManagerMap.get(typeUrl);
  }

  /** Helper method to check if an instance is not null; taken from guava's Precondition.java */
  private static <T> T checkNotNull(T reference) {
    if (reference == null) {
      throw new NullPointerException();
    }
    return reference;
  }

  private synchronized <P> void registerKeyManagerContainer(
      final KeyManagerContainer containerToInsert, boolean forceOverwrite)
      throws GeneralSecurityException {
    String typeUrl = containerToInsert.getUntypedKeyManager().getKeyType();
    KeyManagerContainer container = keyManagerMap.get(typeUrl);
    if (container != null
        && !container.getImplementingClass().equals(containerToInsert.getImplementingClass())) {
      logger.warning("Attempted overwrite of a registered key manager for key type " + typeUrl);
      throw new GeneralSecurityException(
          String.format(
              "typeUrl (%s) is already registered with %s, cannot be re-registered with %s",
              typeUrl,
              container.getImplementingClass().getName(),
              containerToInsert.getImplementingClass().getName()));
    }
    if (!forceOverwrite) {
      keyManagerMap.putIfAbsent(typeUrl, containerToInsert);
    } else {
      keyManagerMap.put(typeUrl, containerToInsert);
    }
  }

  /**
   * Attempts to insert the given KeyManager into the object.
   *
   * <p>If this fails, the KeyManagerRegistry is in an unspecified state and should be discarded.
   */
  synchronized <P> void registerKeyManager(final KeyManager<P> manager)
      throws GeneralSecurityException {
    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
      throw new GeneralSecurityException("Registering key managers is not supported in FIPS mode");
    }
    registerKeyManagerContainer(createContainerFor(manager), /* forceOverwrite= */ false);
  }

  synchronized <KeyProtoT extends MessageLite> void registerKeyManager(
      final KeyTypeManager<KeyProtoT> manager) throws GeneralSecurityException {
    if (!manager.fipsStatus().isCompatible()) {
      throw new GeneralSecurityException(
          "failed to register key manager "
              + manager.getClass()
              + " as it is not FIPS compatible.");
    }
    registerKeyManagerContainer(createContainerFor(manager), /* forceOverwrite= */ false);
  }

  /**
   * Registers a private KeyTypeManager and a corresponding public KeyTypeManager.
   *
   * <p>On the generated Private KeyManager, when we create the public key from a private key, we
   * also call "Validate" on the provided public KeyTypeManager.
   *
   * <p>A call to registerAsymmetricKeyManager takes precedence over other calls (i.e., if the above
   * association is established once, it will stay established).
   */
  synchronized <KeyProtoT extends MessageLite, PublicKeyProtoT extends MessageLite>
      void registerAsymmetricKeyManagers(
          final PrivateKeyTypeManager<KeyProtoT, PublicKeyProtoT> privateKeyTypeManager,
          final KeyTypeManager<PublicKeyProtoT> publicKeyTypeManager)
          throws GeneralSecurityException {
    TinkFipsUtil.AlgorithmFipsCompatibility fipsStatusPrivateKey =
        privateKeyTypeManager.fipsStatus();
    TinkFipsUtil.AlgorithmFipsCompatibility fipsStatusPublicKey = publicKeyTypeManager.fipsStatus();

    if (!fipsStatusPrivateKey.isCompatible()) {
      throw new GeneralSecurityException(
          "failed to register key manager "
              + privateKeyTypeManager.getClass()
              + " as it is not FIPS compatible.");
    }

    if (!fipsStatusPublicKey.isCompatible()) {
      throw new GeneralSecurityException(
          "failed to register key manager "
              + publicKeyTypeManager.getClass()
              + " as it is not FIPS compatible.");
    }

    String privateTypeUrl = privateKeyTypeManager.getKeyType();
    String publicTypeUrl = publicKeyTypeManager.getKeyType();

    if (keyManagerMap.containsKey(privateTypeUrl)
        && keyManagerMap.get(privateTypeUrl).publicKeyManagerClassOrNull() != null) {
      Class<?> existingPublicKeyManagerClass =
          keyManagerMap.get(privateTypeUrl).publicKeyManagerClassOrNull();
      if (existingPublicKeyManagerClass != null) {
        if (!existingPublicKeyManagerClass
            .getName()
            .equals(publicKeyTypeManager.getClass().getName())) {
          logger.warning(
              "Attempted overwrite of a registered key manager for key type "
                  + privateTypeUrl
                  + " with inconsistent public key type "
                  + publicTypeUrl);
          throw new GeneralSecurityException(
              String.format(
                  "public key manager corresponding to %s is already registered with %s, cannot"
                      + " be re-registered with %s",
                  privateKeyTypeManager.getClass().getName(),
                  existingPublicKeyManagerClass.getName(),
                  publicKeyTypeManager.getClass().getName()));
        }
      }
    }

    // We overwrite such that if we once register asymmetrically and once symmetrically, the
    // asymmetric one takes precedence.
    registerKeyManagerContainer(
        createPrivateKeyContainerFor(privateKeyTypeManager, publicKeyTypeManager),
        /* forceOverwrite= */ true);
    registerKeyManagerContainer(
        createContainerFor(publicKeyTypeManager), /* forceOverwrite= */ false);
  }

  boolean typeUrlExists(String typeUrl) {
    return keyManagerMap.containsKey(typeUrl);
  }

  private static String toCommaSeparatedString(Set<Class<?>> setOfClasses) {
    StringBuilder b = new StringBuilder();
    boolean first = true;
    for (Class<?> clazz : setOfClasses) {
      if (!first) {
        b.append(", ");
      }
      b.append(clazz.getCanonicalName());
      first = false;
    }
    return b.toString();
  }

  /**
   * Should not be used since the API is a misuse of Java generics.
   *
   * @deprecated
   */
  @Deprecated
  <P> KeyManager<P> getKeyManager(String typeUrl) throws GeneralSecurityException {
    return getKeyManagerInternal(typeUrl, null);
  }

  /**
   * @return a {@link KeyManager} for the given {@code typeUrl} and {@code primitiveClass}(if found
   *     and this key type supports this primitive).
   */
  <P> KeyManager<P> getKeyManager(String typeUrl, Class<P> primitiveClass)
      throws GeneralSecurityException {
    return getKeyManagerInternal(typeUrl, checkNotNull(primitiveClass));
  }

  private <P> KeyManager<P> getKeyManagerInternal(String typeUrl, Class<P> primitiveClass)
      throws GeneralSecurityException {
    KeyManagerContainer container = getKeyManagerContainerOrThrow(typeUrl);
    if (primitiveClass == null) {
      @SuppressWarnings("unchecked") // Only called from deprecated functions; unavoidable there.
      KeyManager<P> result = (KeyManager<P>) container.getUntypedKeyManager();
      return result;
    }
    if (container.supportedPrimitives().contains(primitiveClass)) {
      return container.getKeyManager(primitiveClass);
    }
    throw new GeneralSecurityException(
        "Primitive type "
            + primitiveClass.getName()
            + " not supported by key manager of type "
            + container.getImplementingClass()
            + ", supported primitives: "
            + toCommaSeparatedString(container.supportedPrimitives()));
  }

  /**
   * @return a {@link KeyManager} for the given {@code typeUrl} (if found).
   */
  KeyManager<?> getUntypedKeyManager(String typeUrl) throws GeneralSecurityException {
    KeyManagerContainer container = getKeyManagerContainerOrThrow(typeUrl);
    return container.getUntypedKeyManager();
  }

  /**
   * Parses the key in a keyData to the corresponding proto message, or returns null.
   *
   * <p>Parsing happens if the key type was registered with a KeyTypeManager. If a legacy KeyManager
   * was used, this returns null.
   */
  MessageLite parseKeyData(KeyData keyData)
      throws GeneralSecurityException, InvalidProtocolBufferException {
    KeyManagerContainer container = getKeyManagerContainerOrThrow(keyData.getTypeUrl());
    return container.parseKey(keyData.getValue());
  }

  boolean isEmpty() {
    return keyManagerMap.isEmpty();
  }
}
