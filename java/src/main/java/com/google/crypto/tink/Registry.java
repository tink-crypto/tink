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

import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Logger;

/**
 * A global container of key managers and catalogues.
 *
 * <p>Registry maps catalogue names to instances of {@link Catalogue} and each supported key type to
 * a corresponding {@link KeyManager} object, which "understands" the key type (i.e., the KeyManager
 * can instantiate the primitive corresponding to given key, or can generate new keys of the
 * supported key type). It holds also a {@link PrimitiveWrapper} for each supported primitive,
 * so that it can wrap a set of primitives (corresponding to a keyset) into a single primitive.
 *
 * <p> Keeping KeyManagers for all primitives in a single Registry (rather than
 * having a separate KeyManager per primitive) enables modular construction of compound primitives
 * from "simple" ones, e.g., AES-CTR-HMAC AEAD encryption uses IND-CPA encryption and a MAC.
 *
 * <p>Registry is initialized at startup, and is later used to instantiate primitives for given keys
 * or keysets. Note that regular users will usually not work directly with Registry, but rather via
 * {@link Config} and {@link KeysetHandle#getPrimitive()}-methods, which in the background register
 * and query the Registry for specific KeyManagers and PrimitiveWrappers. Registry is public though,
 * to enable configurations with custom catalogues, primitives or KeyManagers.
 *
 * <p>To initialize the Registry with all key managers in Tink 1.0.0, one can do as follows:
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
 * <p>After the Registry has been initialized, one can use {@keysetHandle.getPrimitive} to get a
 * primitive. For example, to obtain an {@link Aead} primitive:
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

  private static final ConcurrentMap<String, KeyManager> keyManagerMap =
      new ConcurrentHashMap<String, KeyManager>(); // typeUrl -> KeyManager mapping

  private static final ConcurrentMap<String, Boolean> newKeyAllowedMap =
      new ConcurrentHashMap<String, Boolean>(); // typeUrl -> newKeyAllowed mapping

  private static final ConcurrentMap<String, Catalogue> catalogueMap =
      new ConcurrentHashMap<String, Catalogue>(); //  name -> catalogue mapping

  private static final ConcurrentMap<Class<?>, PrimitiveWrapper<?>> primitiveWrapperMap =
      new ConcurrentHashMap<Class<?>, PrimitiveWrapper<?>>();

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
    newKeyAllowedMap.clear();
    catalogueMap.clear();
    primitiveWrapperMap.clear();
  }

  /**
   * Tries to add a catalogue, to enable custom configuration of key types and key managers.
   *
   * <p>Adding a custom catalogue should be a one-time operaton. There is an existing catalogue,
   * throw exception if {@code catalogue} and the existing catalogue aren't instances of the same
   * class, and do nothing if they are.
   *
   * @throws GeneralSecurityException if there's an existing catalogue is not an instance of the
   *     same class as {@code catalogue}
   */
  public static synchronized void addCatalogue(String catalogueName, Catalogue<?> catalogue)
      throws GeneralSecurityException {
    if (catalogueName == null) {
      throw new IllegalArgumentException("catalogueName must be non-null.");
    }
    if (catalogue == null) {
      throw new IllegalArgumentException("catalogue must be non-null.");
    }
    if (catalogueMap.containsKey(catalogueName.toLowerCase())) {
      Catalogue<?> existing = catalogueMap.get(catalogueName.toLowerCase());
      if (!catalogue.getClass().equals(existing.getClass())) {
        logger.warning(
            "Attempted overwrite of a catalogueName catalogue for name " + catalogueName);
        throw new GeneralSecurityException(
            "catalogue for name " + catalogueName + " has been already registered");
      }
    }
    catalogueMap.put(catalogueName.toLowerCase(), catalogue);
  }

  /**
   * Tries to get a catalogue associated with {@code catalogueName}.
   *
   * @throws GeneralSecurityException if cannot find any catalogue
   */
  public static Catalogue<?> getCatalogue(String catalogueName)
      throws GeneralSecurityException {
    if (catalogueName == null) {
      throw new IllegalArgumentException("catalogueName must be non-null.");
    }
    Catalogue<?> catalogue = catalogueMap.get(catalogueName.toLowerCase());
    if (catalogue == null) {
      String error = String.format("no catalogue found for %s. ", catalogueName);
      if (catalogueName.toLowerCase().startsWith("tinkaead")) {
        error += "Maybe call AeadConfig.register().";
      }
      if (catalogueName.toLowerCase().startsWith("tinkdeterministicaead")) {
        error += "Maybe call DeterministicAeadConfig.register().";
      } else if (catalogueName.toLowerCase().startsWith("tinkstreamingaead")) {
        error += "Maybe call StreamingAeadConfig.register().";
      } else if (catalogueName.toLowerCase().startsWith("tinkhybriddecrypt")
          || catalogueName.toLowerCase().startsWith("tinkhybridencrypt")) {
        error += "Maybe call HybridConfig.register().";
      } else if (catalogueName.toLowerCase().startsWith("tinkmac")) {
        error += "Maybe call MacConfig.register().";
      } else if (catalogueName.toLowerCase().startsWith("tinkpublickeysign")
          || catalogueName.toLowerCase().startsWith("tinkpublickeyverify")) {
        error += "Maybe call SignatureConfig.register().";
      } else if (catalogueName.toLowerCase().startsWith("tink")) {
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
    if (keyManagerMap.containsKey(typeUrl)) {
      KeyManager<P> existingManager = getKeyManager(typeUrl);
      boolean existingNewKeyAllowed = newKeyAllowedMap.get(typeUrl).booleanValue();
      if (!manager.getClass().equals(existingManager.getClass())
          // Disallow changing newKeyAllowed from false to true.
          || ((!existingNewKeyAllowed) && newKeyAllowed)) {
        logger.warning("Attempted overwrite of a registered key manager for key type " + typeUrl);
        throw new GeneralSecurityException(
            String.format(
                "typeUrl (%s) is already registered with %s, cannot be re-registered with %s",
                typeUrl, existingManager.getClass().getName(), manager.getClass().getName()));
      }
    }
    keyManagerMap.put(typeUrl, manager);
    newKeyAllowedMap.put(typeUrl, Boolean.valueOf(newKeyAllowed));
  }

  /**
   * Tries to register {@code manager} for the given {@code typeUrl}. Users can generate new keys
   * with this manager using the {@link Registry#newKey} methods.
   *
   * <p>If there is an existing key manager, throw exception if {@code manager} and the existing
   * key manager aren't instances of the same class, and do nothing if they are.
   *
   * @throws GeneralSecurityException if there's an existing key manager is not an instance of the
   *     class of {@code manager}
   * @deprecated use {@link #registerKeyManager(KeyManager<P>)}
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
   * <p>If there is an existing key manager, throw exception if {@code manager} and the existing
   * key manager aren't instances of the same class, and do nothing if they are.
   *
   * @throws GeneralSecurityException if there's an existing key manager is not an instance of the
   *     class of {@code manager}
   * @deprecated use {@link #registerKeyManager(KeyManager<P>, boolean)}
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
   * <p>If no SetWrapper is registered for {@code P} registers the given one. If already is a
   * SetWrapper registered which is of the same class ass the passed in set wrapper, the call is
   * silently ignored. If the new set wrapper is of a different type, the call fails with a {@code
   * GeneralSecurityException}.
   *
   * @throws GeneralSecurityException if there's an existing key manager is not an instance of the
   *     class of {@code manager}, or the registration tries to re-enable the generation of new
   *     keys.
   */
  public static synchronized <P> void registerPrimitiveWrapper(final PrimitiveWrapper<P> wrapper)
      throws GeneralSecurityException {
    if (wrapper == null) {
      throw new IllegalArgumentException("wrapper must be non-null");
    }
    Class<P> classObject = wrapper.getPrimitiveClass();
    if (primitiveWrapperMap.containsKey(classObject)) {
      PrimitiveWrapper<P> existingWrapper =
          (PrimitiveWrapper<P>) (primitiveWrapperMap.get(classObject));
      if (!wrapper.getClass().equals(existingWrapper.getClass())) {
        logger.warning(
            "Attempted overwrite of a registered SetWrapper for type " + classObject.toString());
        throw new GeneralSecurityException(
            String.format(
                "SetWrapper for primitive (%s) is already registered to be %s, "
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
    return getKeyManagerInternal(typeUrl, null);
  }

  /** @return a {@link KeyManager} for the given {@code typeUrl} (if found). */
  public static <P> KeyManager<P> getKeyManager(String typeUrl, Class<P> primitiveClass)
      throws GeneralSecurityException {
    return getKeyManagerInternal(typeUrl, checkNotNull(primitiveClass));
  }

  @SuppressWarnings("unchecked")
  private static <P> KeyManager<P> getKeyManagerInternal(String typeUrl, Class<P> primitiveClass)
      throws GeneralSecurityException {
    KeyManager<P> manager = keyManagerMap.get(typeUrl);
    if (manager == null) {
      throw new GeneralSecurityException(
          "No key manager found for key type: "
              + typeUrl
              + ".  Check the configuration of the registry.");
    }
    if (primitiveClass != null && !manager.getPrimitiveClass().equals(primitiveClass)) {
      throw new GeneralSecurityException(
          "Primitive type "
              + manager.getPrimitiveClass().getName()
              + " of keymanager for type "
              + typeUrl
              + " does not match requested primitive type "
              + primitiveClass.getName());
    }
    return manager;
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
  public static synchronized KeyData newKeyData(KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    KeyManager<?> manager = getKeyManager(keyTemplate.getTypeUrl());
    if (newKeyAllowedMap.get(keyTemplate.getTypeUrl()).booleanValue()) {
      return manager.newKeyData(keyTemplate.getValue());
    } else {
      throw new GeneralSecurityException(
          "newKey-operation not permitted for key type " + keyTemplate.getTypeUrl());
    }
  }

  /**
   * Convenience method for generating a new key for the specified {@code keyTemplate}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code keyTemplate.type_url}, and calls
   * {@link KeyManager#newKey} with {@code keyTemplate} as the parameter.
   *
   * @return a new key
   */
  public static synchronized MessageLite newKey(KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    KeyManager<?> manager = getKeyManager(keyTemplate.getTypeUrl());
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
   * Creates a set of primitives corresponding to the keys with status=ENABLED in the keyset given
   * in {@code keysetHandle}, assuming all the corresponding key managers are present (keys with
   * status!=ENABLED are skipped).
   *
   * <p>The returned set is usually later "wrapped" into a class that implements the corresponding
   * Primitive-interface.
   *
   * @return a PrimitiveSet with all instantiated primitives
   * @deprecated Use {@code getPrimitives(keysetHandle, Primitive.class)} instead.
   */
  @Deprecated
  public static <P> PrimitiveSet<P> getPrimitives(KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    return getPrimitives(keysetHandle, /* customManager= */ (KeyManager<P>) null);
  }

  /**
   * Creates a set of primitives corresponding to the keys with status=ENABLED in the keyset given
   * in {@code keysetHandle}, assuming all the corresponding key managers are present (keys with
   * status!=ENABLED are skipped).
   *
   * <p>The returned set is usually later "wrapped" into a class that implements the corresponding
   * Primitive-interface.
   *
   * @return a PrimitiveSet with all instantiated primitives
   */
  public static <P> PrimitiveSet<P> getPrimitives(
      KeysetHandle keysetHandle, Class<P> primitiveClass) throws GeneralSecurityException {
    return getPrimitives(keysetHandle, /* customManager= */ null, primitiveClass);
  }

  /**
   * Creates a set of primitives corresponding to the keys with status=ENABLED in the keyset given
   * in {@code keysetHandle}, using {@code customManager} (instead of registered key managers) for
   * keys supported by it. Keys not supported by {@code customManager} are handled by matching
   * registered key managers (if present), and keys with status!=ENABLED are skipped.
   *
   * <p>This enables custom treatment of keys, for example providing extra context (e.g.,
   * credentials for accessing keys managed by a KMS), or gathering custom monitoring/profiling
   * information.
   *
   * <p>The returned set is usually later "wrapped" into a class that implements the corresponding
   * Primitive-interface.
   *
   * @return a PrimitiveSet with all instantiated primitives
   * @deprecated Use {@code getPrimitives(keysetHandle, customManager, Primitive.class)} instead.
   */
  @Deprecated
  public static <P> PrimitiveSet<P> getPrimitives(
      KeysetHandle keysetHandle, final KeyManager<P> customManager)
      throws GeneralSecurityException {
    return getPrimitivesInternal(keysetHandle, customManager, null);
  }

  /**
   * Creates a set of primitives corresponding to the keys with status=ENABLED in the keyset given
   * in {@code keysetHandle}, using {@code customManager} (instead of registered key managers) for
   * keys supported by it. Keys not supported by {@code customManager} are handled by matching
   * registered key managers (if present), and keys with status!=ENABLED are skipped.
   *
   * <p>This enables custom treatment of keys, for example providing extra context (e.g.,
   * credentials for accessing keys managed by a KMS), or gathering custom monitoring/profiling
   * information.
   *
   * <p>The returned set is usually later "wrapped" into a class that implements the corresponding
   * Primitive-interface.
   *
   * @return a PrimitiveSet with all instantiated primitives
   */
  public static <P> PrimitiveSet<P> getPrimitives(
      KeysetHandle keysetHandle, final KeyManager<P> customManager, Class<P> primitiveClass)
      throws GeneralSecurityException {
    return getPrimitivesInternal(keysetHandle, customManager, checkNotNull(primitiveClass));
  }

  private static <P> PrimitiveSet<P> getPrimitivesInternal(
      KeysetHandle keysetHandle, final KeyManager<P> customManager, Class<P> primitiveClass)
      throws GeneralSecurityException {
    Util.validateKeyset(keysetHandle.getKeyset());
    PrimitiveSet<P> primitives = PrimitiveSet.newPrimitiveSet(primitiveClass);
    for (Keyset.Key key : keysetHandle.getKeyset().getKeyList()) {
      if (key.getStatus() == KeyStatusType.ENABLED) {
        P primitive;
        if (customManager != null && customManager.doesSupport(key.getKeyData().getTypeUrl())) {
          primitive = customManager.getPrimitive(key.getKeyData().getValue());
        } else {
          primitive =
              getPrimitiveInternal(
                  key.getKeyData().getTypeUrl(), key.getKeyData().getValue(), primitiveClass);
        }
        PrimitiveSet.Entry<P> entry = primitives.addPrimitive(primitive, key);
        if (key.getKeyId() == keysetHandle.getKeyset().getPrimaryKeyId()) {
          primitives.setPrimary(entry);
        }
      }
    }
    return primitives;
  }

  /**
   * Looks up the globally registered PrimitiveWrapper for this primitive and wraps the given
   * PrimitiveSet with it.
   */
  public static <P> P wrap(PrimitiveSet<P> primitiveSet)
      throws GeneralSecurityException {
    @SuppressWarnings("unchecked") // We know that we only inserted Class<P> -> PrimitiveWrapper<P>
    PrimitiveWrapper<P> wrapper =
        (PrimitiveWrapper<P>) primitiveWrapperMap.get(primitiveSet.getPrimitiveClass());
    if (wrapper == null) {
      throw new GeneralSecurityException(
          "No wrapper found for " + primitiveSet.getPrimitiveClass().getName());
    }
    return wrapper.wrap(primitiveSet);
  }
}
