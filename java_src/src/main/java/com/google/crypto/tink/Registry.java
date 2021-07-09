// Copyright 2017 Google Inc.
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
import com.google.crypto.tink.proto.KeyData;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Logger;

/**
 * A global container of key managers and catalogues.
 *
 * <p>Registry maps each supported key type to a corresponding {@link KeyManager} object, which
 * "understands" the key type (i.e., the KeyManager can instantiate the primitive corresponding to
 * given key, or can generate new keys of the supported key type). It holds also a {@link
 * PrimitiveWrapper} for each supported primitive, so that it can wrap a set of primitives
 * (corresponding to a keyset) into a single primitive.
 *
 * <p>Keeping KeyManagers for all primitives in a single Registry (rather than having a separate
 * KeyManager per primitive) enables modular construction of compound primitives from "simple" ones,
 * e.g., AES-CTR-HMAC AEAD encryption uses IND-CPA encryption and a MAC.
 *
 * <p>Registry is initialized at startup, and is later used to instantiate primitives for given keys
 * or keysets. Note that regular users will usually not work directly with Registry, but rather via
 * {@link TinkConfig} and {@link KeysetHandle#getPrimitive(Class)}-methods, which in the background
 * register and query the Registry for specific KeyManagers and PrimitiveWrappers. Registry is
 * public though, to enable configurations with custom catalogues, primitives or KeyManagers.
 *
 * <p>To initialize the Registry with all key managers:
 *
 * <pre>{@code
 * TinkConfig.register();
 * }</pre>
 *
 * <p>Here's how to register only {@link Aead} key managers:
 *
 * <pre>{@code
 * AeadConfig.register();
 * }</pre>
 *
 * <p>After the Registry has been initialized, one can use get a primitive as follows:
 *
 * <pre>{@code
 * KeysetHandle keysetHandle = ...;
 * Aead aead = keysetHandle.getPrimitive(Aead.class);
 * }</pre>
 *
 * @since 1.0.0
 */
public final class Registry {
  private static final Logger logger = Logger.getLogger(Registry.class.getName());

  private static final ConcurrentMap<String, KeyManagerContainer> keyManagerMap =
      new ConcurrentHashMap<>(); // typeUrl -> KeyManager mapping

  private static final ConcurrentMap<String, KeyDeriverContainer> keyDeriverMap =
      new ConcurrentHashMap<>(); // typeUrl -> deriver (created out of KeyTypeManager).

  private static final ConcurrentMap<String, Boolean> newKeyAllowedMap =
      new ConcurrentHashMap<>(); // typeUrl -> newKeyAllowed mapping

  private static final ConcurrentMap<String, Catalogue<?>> catalogueMap =
      new ConcurrentHashMap<>(); //  name -> catalogue mapping

  private static final ConcurrentMap<Class<?>, PrimitiveWrapper<?, ?>> primitiveWrapperMap =
      new ConcurrentHashMap<>();

  private static final ConcurrentMap<String, KeyTemplate> keyTemplateMap =
      new ConcurrentHashMap<>(); // name -> KeyTemplate mapping

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

    /** Returns some KeyManager from the given one. */
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

  private static interface KeyDeriverContainer {
    KeyData deriveKey(ByteString serializedKeyFormat, InputStream stream)
        throws GeneralSecurityException;
  }

  private static <KeyProtoT extends MessageLite> KeyDeriverContainer createDeriverFor(
      final KeyTypeManager<KeyProtoT> keyManager) {
    return new KeyDeriverContainer() {
      private <KeyFormatProtoT extends MessageLite> MessageLite deriveKeyWithFactory(
          ByteString serializedKeyFormat,
          InputStream stream,
          KeyTypeManager.KeyFactory<KeyFormatProtoT, KeyProtoT> keyFactory)
          throws GeneralSecurityException {
        KeyFormatProtoT keyFormat;
        try {
          keyFormat = keyFactory.parseKeyFormat(serializedKeyFormat);
        } catch (InvalidProtocolBufferException e) {
          throw new GeneralSecurityException("parsing key format failed in deriveKey", e);
        }
        keyFactory.validateKeyFormat(keyFormat);
        return keyFactory.deriveKey(keyFormat, stream);
      }

      @Override
      public KeyData deriveKey(ByteString serializedKeyFormat, InputStream stream)
          throws GeneralSecurityException {
        KeyTypeManager.KeyFactory<?, KeyProtoT> keyFactory = keyManager.keyFactory();
        MessageLite keyValue = deriveKeyWithFactory(serializedKeyFormat, stream, keyFactory);
        return KeyData.newBuilder()
            .setTypeUrl(keyManager.getKeyType())
            .setValue(keyValue.toByteString())
            .setKeyMaterialType(keyManager.keyMaterialType())
            .build();
      }
    };
  }

  private static synchronized KeyManagerContainer getKeyManagerContainerOrThrow(String typeUrl)
      throws GeneralSecurityException {
    if (!keyManagerMap.containsKey(typeUrl)) {
      throw new GeneralSecurityException("No key manager found for key type " + typeUrl);
    }
    return keyManagerMap.get(typeUrl);
  }

  /**
   * Resets the registry.
   *
   * <p>After reset the registry is empty, i.e. it contains no key managers. Thus one might need to
   * call {@code XyzConfig.register()} to re-install the catalogues.
   *
   * <p>This method is intended for testing.
   */
  static synchronized void reset() {
    keyManagerMap.clear();
    keyDeriverMap.clear();
    newKeyAllowedMap.clear();
    catalogueMap.clear();
    primitiveWrapperMap.clear();
    keyTemplateMap.clear();
  }

  /**
   * Tries to add a catalogue, to enable custom configuration of key types and key managers.
   *
   * <p>Adding a custom catalogue should be a one-time operaton. There is an existing catalogue,
   * throw exception if {@code catalogue} and the existing catalogue aren't instances of the same
   * class, and do nothing if they are.
   *
   * @throws GeneralSecurityException if there's an existing catalogue and it is not an instance of
   *     the same class as {@code catalogue}
   * @deprecated Catalogues are no longer supported.
   */
  @Deprecated
  public static synchronized void addCatalogue(String catalogueName, Catalogue<?> catalogue)
      throws GeneralSecurityException {
    if (catalogueName == null) {
      throw new IllegalArgumentException("catalogueName must be non-null.");
    }
    if (catalogue == null) {
      throw new IllegalArgumentException("catalogue must be non-null.");
    }
    if (catalogueMap.containsKey(catalogueName.toLowerCase(Locale.US))) {
      Catalogue<?> existing = catalogueMap.get(catalogueName.toLowerCase(Locale.US));
      if (!catalogue.getClass().getName().equals(existing.getClass().getName())) {
        logger.warning(
            "Attempted overwrite of a catalogueName catalogue for name " + catalogueName);
        throw new GeneralSecurityException(
            "catalogue for name " + catalogueName + " has been already registered");
      }
    }
    catalogueMap.put(catalogueName.toLowerCase(Locale.US), catalogue);
  }

  /**
   * Tries to get a catalogue associated with {@code catalogueName}.
   *
   * @deprecated Catalogues are no longer supported.
   * @throws GeneralSecurityException if no catalogue is found
   */
  @Deprecated
  public static Catalogue<?> getCatalogue(String catalogueName)
      throws GeneralSecurityException {
    if (catalogueName == null) {
      throw new IllegalArgumentException("catalogueName must be non-null.");
    }
    Catalogue<?> catalogue = catalogueMap.get(catalogueName.toLowerCase(Locale.US));
    if (catalogue == null) {
      String error = String.format("no catalogue found for %s. ", catalogueName);
      if (catalogueName.toLowerCase(Locale.US).startsWith("tinkaead")) {
        error += "Maybe call AeadConfig.register().";
      }
      if (catalogueName.toLowerCase(Locale.US).startsWith("tinkdeterministicaead")) {
        error += "Maybe call DeterministicAeadConfig.register().";
      } else if (catalogueName.toLowerCase(Locale.US).startsWith("tinkstreamingaead")) {
        error += "Maybe call StreamingAeadConfig.register().";
      } else if (catalogueName.toLowerCase(Locale.US).startsWith("tinkhybriddecrypt")
          || catalogueName.toLowerCase(Locale.US).startsWith("tinkhybridencrypt")) {
        error += "Maybe call HybridConfig.register().";
      } else if (catalogueName.toLowerCase(Locale.US).startsWith("tinkmac")) {
        error += "Maybe call MacConfig.register().";
      } else if (catalogueName.toLowerCase(Locale.US).startsWith("tinkpublickeysign")
          || catalogueName.toLowerCase(Locale.US).startsWith("tinkpublickeyverify")) {
        error += "Maybe call SignatureConfig.register().";
      } else if (catalogueName.toLowerCase(Locale.US).startsWith("tink")) {
        error += "Maybe call TinkConfig.register().";
      }
      throw new GeneralSecurityException(error);
    }
    return catalogue;
  }

  /**
   * Helper method to check if an instance is not null; taken from guava's Precondition.java
   */
  private static <T> T checkNotNull(T reference) {
    if (reference == null) {
      throw new NullPointerException();
    }
    return reference;
  }

  /**
   * Tries to register {@code manager} for {@code manager.getKeyType()}. Users can generate new keys
   * with this manager using the {@link Registry#newKey} methods.
   *
   * <p>If there is an existing key manager, throws an exception if {@code manager} and the existing
   * key manager aren't instances of the same class, or the existing key manager could not create
   * new keys. Otherwise registration succeeds.
   *
   * @throws GeneralSecurityException if there's an existing key manager is not an instance
   *     of the class of {@code manager}, or the registration tries to re-enable the generation
   *     of new keys.
   */
  public static synchronized <P> void registerKeyManager(final KeyManager<P> manager)
      throws GeneralSecurityException {
    registerKeyManager(manager, /* newKeyAllowed= */ true);
  }

  /**
   * Throws a general security exception if one of these conditions holds:
   *
   * <ul>
   *   <li>There is already a key manager registered for {@code typeURL}, and at least one of the
   *       following is true:
   *       <ul>
   *         <li>The class implementing the existing key manager differs from the given one.
   *         <li>The value of {@code newKeyAllowed} currently registered is false, but the input
   *             parameter is true.
   *       </ul>
   *   <li>The {@code newKeyAllowed} flag is true, and at least one of the following is true:
   *       <ul>
   *         <li>The key manager was already registered, but it contains new key templates.
   *         <li>The key manager is new, but it contains existing key templates.
   */
  private static synchronized <KeyProtoT extends MessageLite, KeyFormatProtoT extends MessageLite>
      void ensureKeyManagerInsertable(
          String typeUrl,
          Class<?> implementingClass,
          Map<String, KeyTypeManager.KeyFactory.KeyFormat<KeyFormatProtoT>> keyFormats,
          boolean newKeyAllowed)
          throws GeneralSecurityException {
    KeyManagerContainer container = keyManagerMap.get(typeUrl);
    if (container != null && !container.getImplementingClass().equals(implementingClass)) {
      logger.warning("Attempted overwrite of a registered key manager for key type " + typeUrl);
      throw new GeneralSecurityException(
          String.format(
              "typeUrl (%s) is already registered with %s, cannot be re-registered with %s",
              typeUrl, container.getImplementingClass().getName(), implementingClass.getName()));
    }
    if (newKeyAllowed && newKeyAllowedMap.containsKey(typeUrl) && !newKeyAllowedMap.get(typeUrl)) {
      throw new GeneralSecurityException("New keys are already disallowed for key type " + typeUrl);
    }

    if (newKeyAllowed) {
      if (keyManagerMap.containsKey(typeUrl)) {
        // When re-inserting an already present KeyTypeManager, no new key templates should be
        // present.
        for (Map.Entry<String, KeyTypeManager.KeyFactory.KeyFormat<KeyFormatProtoT>> entry :
            keyFormats.entrySet()) {
          if (!keyTemplateMap.containsKey(entry.getKey())) {
            throw new GeneralSecurityException(
                "Attempted to register a new key template "
                    + entry.getKey()
                    + " from an existing key manager of type "
                    + typeUrl);
          }
        }
      } else {
        // Check that new key managers can't overwrite existing key templates.
        for (Map.Entry<String, KeyTypeManager.KeyFactory.KeyFormat<KeyFormatProtoT>> entry :
            keyFormats.entrySet()) {

          if (keyTemplateMap.containsKey(entry.getKey())) {
            throw new GeneralSecurityException(
                "Attempted overwrite of a registered key template " + entry.getKey());
          }
        }
      }
    }
  }

  /**
   * Tries to register {@code manager} for {@code manager.getKeyType()}. If {@code newKeyAllowed} is
   * true, users can generate new keys with this manager using the {@link Registry#newKey} methods.
   *
   * <p>If there is an existing key manager, throws an exception if {@code manager} and the existing
   * key manager aren't instances of the same class, or if {@code newKeyAllowed} is true while the
   * existing key manager could not create new keys.  Otherwise registration succeeds.
   *
   * @throws GeneralSecurityException if there's an existing key manager is not an instance
   *     of the class of {@code manager}, or the registration tries to re-enable the generation
   *     of new keys.
   */
  public static synchronized <P> void registerKeyManager(
      final KeyManager<P> manager, boolean newKeyAllowed) throws GeneralSecurityException {
    if (manager == null) {
      throw new IllegalArgumentException("key manager must be non-null.");
    }
    String typeUrl = manager.getKeyType();
    // Use an empty key format because old-style key managers don't export their key formats
    ensureKeyManagerInsertable(typeUrl, manager.getClass(), Collections.emptyMap(), newKeyAllowed);
    keyManagerMap.putIfAbsent(typeUrl, createContainerFor(manager));
    newKeyAllowedMap.put(typeUrl, Boolean.valueOf(newKeyAllowed));
  }

  /**
   * Tries to register {@code manager} for {@code manager.getKeyType()}. If {@code newKeyAllowed} is
   * true, users can generate new keys with this manager using the {@link Registry#newKey} methods.
   *
   * <p>If there is an existing key manager, throws an exception if {@code manager} and the existing
   * key manager aren't instances of the same class, or if {@code newKeyAllowed} is true while the
   * existing key manager could not create new keys. Otherwise registration succeeds.
   *
   * <p>If {@code newKeyAllowed} is true, also tries to register the key templates supported by
   * {@code manager}.
   *
   * @throws GeneralSecurityException if there's an existing key manager is not an instance of the
   *     class of {@code manager}, or the registration tries to re-enable the generation of new
   *     keys.
   * @throws GeneralSecurityException if there's an existing key template.
   */
  public static synchronized <KeyProtoT extends MessageLite> void registerKeyManager(
      final KeyTypeManager<KeyProtoT> manager, boolean newKeyAllowed)
      throws GeneralSecurityException {
    if (manager == null) {
      throw new IllegalArgumentException("key manager must be non-null.");
    }
    String typeUrl = manager.getKeyType();
    ensureKeyManagerInsertable(
        typeUrl,
        manager.getClass(),
        newKeyAllowed ? manager.keyFactory().keyFormats() : Collections.emptyMap(),
        newKeyAllowed);

    if (!keyManagerMap.containsKey(typeUrl)) {
      keyManagerMap.put(typeUrl, createContainerFor(manager));
      keyDeriverMap.put(typeUrl, createDeriverFor(manager));
      if (newKeyAllowed) {
        registerKeyTemplates(typeUrl, manager.keyFactory().keyFormats());
      }
    }
    newKeyAllowedMap.put(typeUrl, Boolean.valueOf(newKeyAllowed));
  }

  /**
   * Tries to register {@code manager} for {@code manager.getKeyType()}. If {@code newKeyAllowed} is
   * true, users can generate new keys with this manager using the {@link Registry#newKey} methods.
   *
   * <p>If {@code newKeyAllowed} is true, also tries to register the key templates supported by
   * {@code manager}.
   *
   * <p>If there is an existing key manager, throws an exception if {@code manager} and the existing
   * key manager aren't instances of the same class, or if {@code newKeyAllowed} is true while the
   * existing key manager could not create new keys. Otherwise registration succeeds.
   *
   * @throws GeneralSecurityException if there's an existing key manager is not an instance of the
   *     class of {@code manager}, or the registration tries to re-enable the generation of new
   *     keys.
   * @throws GeneralSecurityException if there's an existing key template.
   */
  public static synchronized <KeyProtoT extends MessageLite, PublicKeyProtoT extends MessageLite>
      void registerAsymmetricKeyManagers(
          final PrivateKeyTypeManager<KeyProtoT, PublicKeyProtoT> privateKeyTypeManager,
          final KeyTypeManager<PublicKeyProtoT> publicKeyTypeManager,
          boolean newKeyAllowed)
          throws GeneralSecurityException {
    if (privateKeyTypeManager == null || publicKeyTypeManager == null) {
      throw new IllegalArgumentException("given key managers must be non-null.");
    }
    String privateTypeUrl = privateKeyTypeManager.getKeyType();
    String publicTypeUrl = publicKeyTypeManager.getKeyType();
    ensureKeyManagerInsertable(
        privateTypeUrl,
        privateKeyTypeManager.getClass(),
        newKeyAllowed ? privateKeyTypeManager.keyFactory().keyFormats() : Collections.emptyMap(),
        newKeyAllowed);
    // No key format because a public key manager cannot create new keys
    ensureKeyManagerInsertable(
        publicTypeUrl, publicKeyTypeManager.getClass(), Collections.emptyMap(), false);
    if (privateTypeUrl.equals(publicTypeUrl)) {
      throw new GeneralSecurityException("Private and public key type must be different.");
    }

    if (keyManagerMap.containsKey(privateTypeUrl)) {
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

    if (!keyManagerMap.containsKey(privateTypeUrl)
        || keyManagerMap.get(privateTypeUrl).publicKeyManagerClassOrNull() == null) {
      keyManagerMap.put(
          privateTypeUrl,
          createPrivateKeyContainerFor(privateKeyTypeManager, publicKeyTypeManager));
      keyDeriverMap.put(privateTypeUrl, createDeriverFor(privateKeyTypeManager));
      if (newKeyAllowed) {
        registerKeyTemplates(
            privateKeyTypeManager.getKeyType(), privateKeyTypeManager.keyFactory().keyFormats());
      }
    }
    newKeyAllowedMap.put(privateTypeUrl, newKeyAllowed);
    if (!keyManagerMap.containsKey(publicTypeUrl)) {
      keyManagerMap.put(publicTypeUrl, createContainerFor(publicKeyTypeManager));
      // We do not allow key derivation for public key types. It doesn't seem like this would make
      // sense.
    }
    newKeyAllowedMap.put(publicTypeUrl, false);
  }

  private static <KeyFormatProtoT extends MessageLite> void registerKeyTemplates(
      String typeUrl,
      Map<String, KeyTypeManager.KeyFactory.KeyFormat<KeyFormatProtoT>> keyFormats) {
    for (Map.Entry<String, KeyTypeManager.KeyFactory.KeyFormat<KeyFormatProtoT>> entry :
        keyFormats.entrySet()) {
      keyTemplateMap.put(
          entry.getKey(),
          KeyTemplate.create(
              typeUrl,
              entry.getValue().keyFormat.toByteArray(),
              entry.getValue().outputPrefixType));
    }
  }

  /**
   * Tries to register {@code manager} for the given {@code typeUrl}. Users can generate new keys
   * with this manager using the {@link Registry#newKey} methods.
   *
   * <p>Does nothing if there's an existing key manager and it's an instance of the same class as
   * {@code manager}.
   *
   * @throws GeneralSecurityException if there's an existing key manager and it is not an instance
   *     of the same class as {@code manager}
   * @deprecated use {@link #registerKeyManager(KeyManager) registerKeyManager(KeyManager&lt;P&gt;)}
   */
  @Deprecated
  public static synchronized <P> void registerKeyManager(
      String typeUrl, final KeyManager<P> manager) throws GeneralSecurityException {
    registerKeyManager(typeUrl, manager, /* newKeyAllowed= */ true);
  }

  /**
   * Tries to register {@code manager} for the given {@code typeUrl}. If {@code newKeyAllowed} is
   * true, users can generate new keys with this manager using the {@link Registry#newKey} methods.
   *
   * <p>Does nothing if there's an existing key manager and it's an instance of the same class as
   * {@code manager}.
   *
   * @throws GeneralSecurityException if there's an existing key manager and it is not an instance
   *     of the same class as {@code manager}
   * @deprecated use {@link #registerKeyManager(KeyManager, boolean)
   *     registerKeyManager(KeyManager&lt;P&gt;, boolean)}
   */
  @Deprecated
  public static synchronized <P> void registerKeyManager(
      String typeUrl, final KeyManager<P> manager, boolean newKeyAllowed)
      throws GeneralSecurityException {
    if (manager == null) {
      throw new IllegalArgumentException("key manager must be non-null.");
    }
    if (!typeUrl.equals(manager.getKeyType())) {
      throw new GeneralSecurityException("Manager does not support key type "
          + typeUrl + ".");
    }
    registerKeyManager(manager, newKeyAllowed);
  }

  /**
   * Tries to register {@code wrapper} as a new SetWrapper for primitive {@code P}.
   *
   * <p>If no SetWrapper is registered for {@code P}, registers the given one. If there already is a
   * SetWrapper registered which is of the same class ass the passed in set wrapper, the call is
   * silently ignored. If the new set wrapper is of a different type, the call fails with a {@code
   * GeneralSecurityException}.
   *
   * @throws GeneralSecurityException if there's an existing key manager and it is not an instance
   *     of the class of {@code manager}, or the registration tries to re-enable the generation of
   *     new keys.
   */
  public static synchronized <B, P> void registerPrimitiveWrapper(
      final PrimitiveWrapper<B, P> wrapper) throws GeneralSecurityException {
    if (wrapper == null) {
      throw new IllegalArgumentException("wrapper must be non-null");
    }
    Class<P> classObject = wrapper.getPrimitiveClass();
    if (primitiveWrapperMap.containsKey(classObject)) {
      @SuppressWarnings("unchecked") // We know that we only inserted objects of the correct type.
      PrimitiveWrapper<?, P> existingWrapper =
          (PrimitiveWrapper<?, P>) primitiveWrapperMap.get(classObject);
      if (!wrapper.getClass().getName().equals(existingWrapper.getClass().getName())) {
        logger.warning(
            "Attempted overwrite of a registered PrimitiveWrapper for type " + classObject);
        throw new GeneralSecurityException(
            String.format(
                "PrimitiveWrapper for primitive (%s) is already registered to be %s, "
                    + "cannot be re-registered with %s",
                classObject.getName(),
                existingWrapper.getClass().getName(),
                wrapper.getClass().getName()));
      }
    }
    primitiveWrapperMap.put(classObject, wrapper);
  }

  /**
   * @return a {@link KeyManager} for the given {@code typeUrl} (if found).
   * @deprecated Use {@code getKeyManager(typeUrl, Primitive.class)} or
   * {@code getUntypedKeyManager typeUrl} instead.
   */
  @Deprecated
  public static <P> KeyManager<P> getKeyManager(String typeUrl) throws GeneralSecurityException {
    return getKeyManagerInternal(typeUrl, null);
  }

  /** @return a {@link KeyManager} for the given {@code typeUrl} (if found). */
  public static KeyManager<?> getUntypedKeyManager(String typeUrl)
      throws GeneralSecurityException {
    KeyManagerContainer container = getKeyManagerContainerOrThrow(typeUrl);
    return container.getUntypedKeyManager();
  }

  /** @return a {@link KeyManager} for the given {@code typeUrl} (if found). */
  public static <P> KeyManager<P> getKeyManager(String typeUrl, Class<P> primitiveClass)
      throws GeneralSecurityException {
    return getKeyManagerInternal(typeUrl, checkNotNull(primitiveClass));
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

  private static <P> KeyManager<P> getKeyManagerInternal(String typeUrl, Class<P> primitiveClass)
      throws GeneralSecurityException {
    KeyManagerContainer container = getKeyManagerContainerOrThrow(typeUrl);
    if (primitiveClass == null) {
      @SuppressWarnings("unchecked")  // Only called from deprecated functions; unavoidable there.
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
   * Convenience method for generating a new {@link KeyData} for the specified {@code template}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code keyTemplate.type_url}, and calls
   * {@link KeyManager#newKeyData}.
   *
   * <p>This method should be used solely for key management.
   *
   * @return a new {@link KeyData}
   */
  public static synchronized KeyData
      newKeyData(com.google.crypto.tink.proto.KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    KeyManager<?> manager = getUntypedKeyManager(keyTemplate.getTypeUrl());
    if (newKeyAllowedMap.get(keyTemplate.getTypeUrl()).booleanValue()) {
      return manager.newKeyData(keyTemplate.getValue());
    } else {
      throw new GeneralSecurityException(
          "newKey-operation not permitted for key type " + keyTemplate.getTypeUrl());
    }
  }

    /**
   * Convenience method for generating a new {@link KeyData} for the specified {@code template}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code keyTemplate.type_url}, and calls
   * {@link KeyManager#newKeyData}.
   *
   * <p>This method should be used solely for key management.
   *
   * @return a new {@link KeyData}
   */
  public static synchronized KeyData newKeyData(com.google.crypto.tink.KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    return newKeyData(keyTemplate.getProto());
  }

  /**
   * Convenience method for generating a new key for the specified {@code keyTemplate}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code keyTemplate.type_url}, and calls
   * {@link KeyManager#newKey} with {@code keyTemplate} as the parameter.
   *
   * @return a new key
   */
  public static synchronized MessageLite newKey(
      com.google.crypto.tink.proto.KeyTemplate keyTemplate) throws GeneralSecurityException {
    KeyManager<?> manager = getUntypedKeyManager(keyTemplate.getTypeUrl());
    if (newKeyAllowedMap.get(keyTemplate.getTypeUrl()).booleanValue()) {
      return manager.newKey(keyTemplate.getValue());
    } else {
      throw new GeneralSecurityException(
          "newKey-operation not permitted for key type " + keyTemplate.getTypeUrl());
    }
  }

  /**
   * Convenience method for generating a new key for the specified {@code format}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code keyTemplate.type_url}, and calls
   * {@link KeyManager#newKey} with {@code format} as the parameter.
   *
   * @return a new key
   */
  public static synchronized MessageLite newKey(String typeUrl, MessageLite format)
      throws GeneralSecurityException {
    KeyManager<?> manager = getKeyManager(typeUrl);
    if (newKeyAllowedMap.get(typeUrl).booleanValue()) {
      return manager.newKey(format);
    } else {
      throw new GeneralSecurityException("newKey-operation not permitted for key type " + typeUrl);
    }
  }

  /**
   * Method to derive a key, using the given {@code keyTemplate}, with the randomness as provided by
   * the second argument.
   *
   * <p>This method is on purpose not in the public interface. Calling it twice using different key
   * templates and the same randomness can completely destroy any security in a system, so we
   * prevent this by making it accessible only to safe call sites.
   *
   * <p>This functions ignores {@code keyTemplate.getOutputPrefix()}.
   */
  static synchronized KeyData deriveKey(
      com.google.crypto.tink.proto.KeyTemplate keyTemplate, InputStream randomStream)
      throws GeneralSecurityException {
    String typeUrl = keyTemplate.getTypeUrl();
    if (!keyDeriverMap.containsKey(typeUrl)) {
      throw new GeneralSecurityException(
          "No keymanager registered or key manager cannot derive keys for " + typeUrl);
    }
    KeyDeriverContainer deriver = keyDeriverMap.get(typeUrl);
    return deriver.deriveKey(keyTemplate.getValue(), randomStream);
  }

  /**
   * Convenience method for extracting the public key data from the private key given in {@code
   * serializedPrivateKey}.
   *
   * <p>It looks up a {@link PrivateKeyManager} identified by {@code typeUrl}, and calls {@link
   * PrivateKeyManager#getPublicKeyData} with {@code serializedPrivateKey} as the parameter.
   *
   * @return a new key
   */
  public static KeyData getPublicKeyData(String typeUrl, ByteString serializedPrivateKey)
      throws GeneralSecurityException {
    KeyManager<?> manager = getKeyManager(typeUrl);
    if (!(manager instanceof PrivateKeyManager)) {
      throw new GeneralSecurityException(
          "manager for key type " + typeUrl + " is not a PrivateKeyManager");
    }
    return ((PrivateKeyManager) manager).getPublicKeyData(serializedPrivateKey);
  }

  /**
   * Convenience method for creating a new primitive for the key given in {@code proto}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code type_url}, and calls {@link
   * KeyManager#getPrimitive} with {@code key} as the parameter.
   *
   * @return a new primitive
   * @deprecated Use {@code getPrimitive(typeUrl, key, P.class)} instead.
   */
  @Deprecated
  @SuppressWarnings("TypeParameterUnusedInFormals")
  public static <P> P getPrimitive(String typeUrl, MessageLite key)
      throws GeneralSecurityException {
    return getPrimitiveInternal(typeUrl, key, null);
  }

  /**
   * Convenience method for creating a new primitive for the key given in {@code key}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code type_url}, and calls {@link
   * KeyManager#getPrimitive} with {@code key} as the parameter.
   *
   * @return a new primitive
   */
  public static <P> P getPrimitive(String typeUrl, MessageLite key, Class<P> primitiveClass)
      throws GeneralSecurityException {
    return getPrimitiveInternal(typeUrl, key, checkNotNull(primitiveClass));
  }

  private static <P> P getPrimitiveInternal(
      String typeUrl, MessageLite key, Class<P> primitiveClass) throws GeneralSecurityException {
    KeyManager<P> manager = getKeyManagerInternal(typeUrl, primitiveClass);
    return manager.getPrimitive(key);
  }

  /**
   * Convenience method for creating a new primitive for the key given in {@code proto}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code type_url}, and calls {@link
   * KeyManager#getPrimitive} with {@code serializedKey} as the parameter.
   *
   * @return a new primitive
   * @deprecated Use {@code getPrimitive(typeUrl, serializedKey, Primitive.class} instead.
   */
  @Deprecated
  @SuppressWarnings("TypeParameterUnusedInFormals")
  public static <P> P getPrimitive(String typeUrl, ByteString serializedKey)
      throws GeneralSecurityException {
    return getPrimitiveInternal(typeUrl, serializedKey, null);
  }

  /**
   * Convenience method for creating a new primitive for the key given in {@code serializedKey}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code type_url}, and calls {@link
   * KeyManager#getPrimitive} with {@code serialized} as the parameter.
   *
   * @return a new primitive
   */
  public static <P> P getPrimitive(
      String typeUrl, ByteString serializedKey, Class<P> primitiveClass)
      throws GeneralSecurityException {
    return getPrimitiveInternal(typeUrl, serializedKey, checkNotNull(primitiveClass));
  }

  private static <P> P getPrimitiveInternal(
      String typeUrl, ByteString serializedKey, Class<P> primitiveClass)
      throws GeneralSecurityException {
    KeyManager<P> manager = getKeyManagerInternal(typeUrl, primitiveClass);
    return manager.getPrimitive(serializedKey);
  }

  /**
   * Convenience method for creating a new primitive for the key given in {@code serializedKey}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code type_url}, and calls {@link
   * KeyManager#getPrimitive} with {@code serialized} as the parameter.
   *
   * @deprecated Use {@code getPrimitive(typeUrl, serializedKey, Primitive.class)} instead.
   * @return a new primitive
   */
  @Deprecated
  @SuppressWarnings("TypeParameterUnusedInFormals")
  public static <P> P getPrimitive(String typeUrl, byte[] serializedKey)
      throws GeneralSecurityException {
    return getPrimitive(typeUrl, ByteString.copyFrom(serializedKey));
  }
  /**
   * Convenience method for creating a new primitive for the key given in {@code serializedKey}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code type_url}, and calls {@link
   * KeyManager#getPrimitive} with {@code serialized} as the parameter.
   *
   * @return a new primitive
   */
  public static <P> P getPrimitive(String typeUrl, byte[] serializedKey, Class<P> primitiveClass)
      throws GeneralSecurityException {
    return getPrimitive(typeUrl, ByteString.copyFrom(serializedKey), primitiveClass);
  }

  /**
   * Convenience method for creating a new primitive for the key given in {@code keyData}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code keyData.type_url}, and calls {@link
   * KeyManager#getPrimitive} with {@code keyData.value} as the parameter.
   *
   * @return a new primitive
   * @deprecated Use {@code getPrimitive(keyData, Primitive.class)} instead.
   */
  @Deprecated
  @SuppressWarnings("TypeParameterUnusedInFormals")
  public static <P> P getPrimitive(KeyData keyData) throws GeneralSecurityException {
    return getPrimitive(keyData.getTypeUrl(), keyData.getValue());
  }

  /**
   * Convenience method for creating a new primitive for the key given in {@code keyData}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code keyData.type_url}, and calls {@link
   * KeyManager#getPrimitive} with {@code keyData.value} as the parameter.
   *
   * @return a new primitive
   */
  public static <P> P getPrimitive(KeyData keyData, Class<P> primitiveClass)
      throws GeneralSecurityException {
    return getPrimitive(keyData.getTypeUrl(), keyData.getValue(), primitiveClass);
  }

  /**
   * Looks up the globally registered PrimitiveWrapper for this primitive and wraps the given
   * PrimitiveSet with it.
   */
  public static <B, P> P wrap(PrimitiveSet<B> primitiveSet, Class<P> clazz)
      throws GeneralSecurityException {
    @SuppressWarnings("unchecked") // We know that we inserted Class<P> -> PrimitiveWrapper<?, P>
    PrimitiveWrapper<?, P> wrapper = (PrimitiveWrapper<?, P>) primitiveWrapperMap.get(clazz);
    if (wrapper == null) {
      throw new GeneralSecurityException(
          "No wrapper found for " + primitiveSet.getPrimitiveClass().getName());
    }
    if (!wrapper.getInputPrimitiveClass().equals(primitiveSet.getPrimitiveClass())) {
      throw new GeneralSecurityException(
          "Wrong input primitive class, expected "
              + wrapper.getInputPrimitiveClass()
              + ", got "
              + primitiveSet.getPrimitiveClass());
    }
    @SuppressWarnings("unchecked") // We just checked correctness
    P result = ((PrimitiveWrapper<B, P>) wrapper).wrap(primitiveSet);
    return result;
  }

  public static <P> P wrap(PrimitiveSet<P> primitiveSet)
      throws GeneralSecurityException {
    return wrap(primitiveSet, primitiveSet.getPrimitiveClass());
  }

  /**
   * Returns an immutable list of key template names supported by registered key managers that are
   * allowed to generate new keys.
   *
   * @since 1.6.0
   */
  public static synchronized List<String> keyTemplates() {
    List<String> results = new ArrayList<>();
    for (String name : keyTemplateMap.keySet()) {
      results.add(name);
    }

    return Collections.unmodifiableList(results);
  }

  /** Internal API that returns an unmodifiable map of registered key templates and their names. */
  static synchronized Map<String, KeyTemplate> keyTemplateMap() {
    return Collections.unmodifiableMap(keyTemplateMap);
  }
  /**
   * Returns the input primitive required when creating a {@code wrappedPrimitive}.
   *
   * <p>This returns the primitive class of the objects required when we want to create a wrapped
   * primitive of type {@code wrappedPrimitive}. Returns {@code null} if no wrapper for this
   * primitive has been registered.
   */
  public static Class<?> getInputPrimitive(Class<?> wrappedPrimitive) {
    PrimitiveWrapper<?, ?> wrapper = primitiveWrapperMap.get(wrappedPrimitive);
    if (wrapper == null) {
      return null;
    }
    return wrapper.getInputPrimitiveClass();
  }

  /**
   * Returns the key proto in the keyData if a corresponding key type manager was registered.
   * Returns null if the key type was registered with a {@link KeyManager} (and not a {@link
   * KeyTypeManager}).
   */
  static MessageLite parseKeyData(KeyData keyData)
      throws GeneralSecurityException, InvalidProtocolBufferException {
    KeyManagerContainer container = getKeyManagerContainerOrThrow(keyData.getTypeUrl());
    return container.parseKey(keyData.getValue());
  }

  /**
   * Tries to enable the FIPS restrictions if the Registry is empty.
   *
   * @throws GeneralSecurityException if any key manager has already been registered.
   */
  public static synchronized <P> void restrictToFipsIfEmpty() throws GeneralSecurityException {
    if (keyManagerMap.isEmpty()) {
      TinkFipsUtil.setFipsRestricted();
      return;
    }
    throw new GeneralSecurityException("Could not enable FIPS mode as Registry is not empty.");
  }

  private Registry() {}
}
