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
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrivateKeyTypeManager;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.proto.KeyData;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;
import javax.annotation.Nullable;

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

  private static final AtomicReference<KeyManagerRegistry> keyManagerRegistry =
      new AtomicReference<>(new KeyManagerRegistry());

  private static final ConcurrentMap<String, Boolean> newKeyAllowedMap =
      new ConcurrentHashMap<>(); // typeUrl -> newKeyAllowed mapping

  private static final ConcurrentMap<String, Catalogue<?>> catalogueMap =
      new ConcurrentHashMap<>(); //  name -> catalogue mapping

  /**
   * Resets the registry.
   *
   * <p>After reset the registry is empty, i.e. it contains no key managers. Thus one might need to
   * call {@code XyzConfig.register()} to re-install the catalogues.
   *
   * <p>This method is intended for testing.
   */
  static synchronized void reset() {
    keyManagerRegistry.set(new KeyManagerRegistry());
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    newKeyAllowedMap.clear();
    catalogueMap.clear();
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
  public static synchronized void addCatalogue(
      String catalogueName, Catalogue<?> catalogue) throws GeneralSecurityException {
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
   * Tries to register {@code manager} for {@code manager.getKeyType()}. Users can generate new keys
   * with this manager using the {@link Registry#newKey} methods.
   *
   * <p>If there is an existing key manager, throws an exception if {@code manager} and the existing
   * key manager aren't instances of the same class, or the existing key manager could not create
   * new keys. Otherwise registration succeeds.
   *
   * @throws GeneralSecurityException if there's an existing key manager is not an instance of the
   *     class of {@code manager}, or the registration tries to re-enable the generation of new
   *     keys.
   */
  public static synchronized <P> void registerKeyManager(final KeyManager<P> manager)
      throws GeneralSecurityException {
    registerKeyManager(manager, /* newKeyAllowed= */ true);
  }

  private static Set<Class<?>> createAllowedPrimitives() {
    HashSet<Class<?>> result = new HashSet<>();
    result.add(Aead.class);
    result.add(DeterministicAead.class);
    result.add(StreamingAead.class);
    result.add(HybridEncrypt.class);
    result.add(HybridDecrypt.class);
    result.add(Mac.class);
    result.add(Prf.class);
    result.add(PublicKeySign.class);
    result.add(PublicKeyVerify.class);
    return result;
  }

  private static final Set<Class<?>> ALLOWED_PRIMITIVES =
      Collections.unmodifiableSet(createAllowedPrimitives());

  /**
   * Tries to register {@code manager} for {@code manager.getKeyType()}. If {@code newKeyAllowed} is
   * true, users can generate new keys with this manager using the {@link Registry#newKey} methods.
   *
   * <p>If there is an existing key manager, throws an exception if {@code manager} and the existing
   * key manager aren't instances of the same class, or if {@code newKeyAllowed} is true while the
   * existing key manager could not create new keys. Otherwise registration succeeds.
   *
   * @throws GeneralSecurityException if there's an existing key manager is not an instance of the
   *     class of {@code manager}, or the registration tries to re-enable the generation of new
   *     keys.
   */
  public static synchronized <P> void registerKeyManager(
      final KeyManager<P> manager, boolean newKeyAllowed) throws GeneralSecurityException {
    if (manager == null) {
      throw new IllegalArgumentException("key manager must be non-null.");
    }
    if (!ALLOWED_PRIMITIVES.contains(manager.getPrimitiveClass())) {
      throw new GeneralSecurityException(
          "Registration of key managers for class "
              + manager.getPrimitiveClass()
              + " has been disabled. Please file an issue on"
              + " https://github.com/tink-crypto/tink-java");
    }
    KeyManagerRegistry newKeyManagerRegistry = new KeyManagerRegistry(keyManagerRegistry.get());
    newKeyManagerRegistry.registerKeyManager(manager);

    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
      throw new GeneralSecurityException("Registering key managers is not supported in FIPS mode");
    }
    String typeUrl = manager.getKeyType();
    // Use an empty key format because old-style key managers don't export their key formats
    ensureKeyManagerInsertable(typeUrl, newKeyAllowed);
    newKeyAllowedMap.put(typeUrl, Boolean.valueOf(newKeyAllowed));
    keyManagerRegistry.set(newKeyManagerRegistry);
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
   * @throws GeneralSecurityException if the key manager is not compatible with the restrictions in
   *     FIPS-mode.
   */
  public static synchronized <KeyProtoT extends MessageLite> void registerKeyManager(
      final KeyTypeManager<KeyProtoT> manager, boolean newKeyAllowed)
      throws GeneralSecurityException {
    if (manager == null) {
      throw new IllegalArgumentException("key manager must be non-null.");
    }
    KeyManagerRegistry newKeyManagerRegistry = new KeyManagerRegistry(keyManagerRegistry.get());
    newKeyManagerRegistry.registerKeyManager(manager);
    String typeUrl = manager.getKeyType();
    ensureKeyManagerInsertable(typeUrl, newKeyAllowed);

    newKeyAllowedMap.put(typeUrl, Boolean.valueOf(newKeyAllowed));
    keyManagerRegistry.set(newKeyManagerRegistry);
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
      throw new GeneralSecurityException("Manager does not support key type " + typeUrl + ".");
    }
    registerKeyManager(manager, newKeyAllowed);
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
  private static synchronized void ensureKeyManagerInsertable(String typeUrl, boolean newKeyAllowed)
      throws GeneralSecurityException {
    if (newKeyAllowed && newKeyAllowedMap.containsKey(typeUrl) && !newKeyAllowedMap.get(typeUrl)) {
      throw new GeneralSecurityException("New keys are already disallowed for key type " + typeUrl);
    }
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
    KeyManagerRegistry newKeyManagerRegistry = new KeyManagerRegistry(keyManagerRegistry.get());
    newKeyManagerRegistry.registerAsymmetricKeyManagers(
        privateKeyTypeManager, publicKeyTypeManager);

    String privateTypeUrl = privateKeyTypeManager.getKeyType();
    String publicTypeUrl = publicKeyTypeManager.getKeyType();
    ensureKeyManagerInsertable(privateTypeUrl, newKeyAllowed);
    // No key format because a public key manager cannot create new keys
    ensureKeyManagerInsertable(publicTypeUrl, false);

    newKeyAllowedMap.put(privateTypeUrl, newKeyAllowed);
    newKeyAllowedMap.put(publicTypeUrl, false);

    keyManagerRegistry.set(newKeyManagerRegistry);
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
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(wrapper);
  }

  /**
   * Returns a {@link KeyManager} for the given {@code typeUrl} (if found).
   *
   * @deprecated KeyManagers should not be used directly. Use {@code newKeyData} or {@code
   *     getPrimitive} instead.
   */
  @Deprecated
  public static <P> KeyManager<P> getKeyManager(String typeUrl)
      throws GeneralSecurityException {
    @SuppressWarnings("unchecked") // Unavoidable for the API we implement (hence it is deprecated)
    KeyManager<P> result = (KeyManager<P>) getUntypedKeyManager(typeUrl);
    return result;
  }

  /**
   * Returns a {@link KeyManager} for the given {@code typeUrl} (if found).
   *
   * @deprecated KeyManagers should not be used directly. Use {@code newKeyData} or {@code
   *     getPrimitive} instead.
   */
  @Deprecated
  public static <P> KeyManager<P> getKeyManager(String typeUrl, Class<P> primitiveClass)
      throws GeneralSecurityException {
    return keyManagerRegistry.get().getKeyManager(typeUrl, primitiveClass);
  }

  /**
   * Returns a {@link KeyManager} for the given {@code typeUrl} (if found).
   *
   * @deprecated KeyManagers should not be used directly. Use {@code newKeyData} or {@code
   *     getPrimitive} instead.
   */
  @Deprecated
  public static KeyManager<?> getUntypedKeyManager(String typeUrl)
      throws GeneralSecurityException {
    return keyManagerRegistry.get().getUntypedKeyManager(typeUrl);
  }

  /**
   * Generates a new {@link KeyData} for the specified {@code template}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code keyTemplate.type_url}, and calls
   * {@link KeyManager#newKeyData}.
   *
   * <p>This method should be used solely for key management.
   *
   * @return a new {@link KeyData}
   */
  public static synchronized KeyData newKeyData(
      com.google.crypto.tink.proto.KeyTemplate keyTemplate) throws GeneralSecurityException {
    KeyManager<?> manager = keyManagerRegistry.get().getUntypedKeyManager(keyTemplate.getTypeUrl());
    if (newKeyAllowedMap.get(keyTemplate.getTypeUrl()).booleanValue()) {
      return manager.newKeyData(keyTemplate.getValue());
    } else {
      throw new GeneralSecurityException(
          "newKey-operation not permitted for key type " + keyTemplate.getTypeUrl());
    }
  }

  /**
   * Generates a new {@link KeyData} for the specified {@code template}.
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
    byte[] serializedKeyTemplate = TinkProtoParametersFormat.serialize(keyTemplate.toParameters());
    try {
      return newKeyData(
          com.google.crypto.tink.proto.KeyTemplate.parseFrom(
              serializedKeyTemplate, ExtensionRegistryLite.getEmptyRegistry()));
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Failed to parse serialized parameters", e);
    }
  }

  /**
   * Generates a new key for the specified {@code keyTemplate}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code keyTemplate.type_url}, and calls
   * {@link KeyManager#newKey} with {@code keyTemplate} as the parameter.
   *
   * @return a new key
   * @deprecated Use {@code newKeyData} instead.
   */
  @Deprecated
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
   * Generates a new key for the specified {@code format}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code keyTemplate.type_url}, and calls
   * {@link KeyManager#newKey} with {@code format} as the parameter.
   *
   * @return a new key
   * @deprecated Use {@code newKeyData} instead.
   */
  @Deprecated
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
   * Extracts the public key data from the private key given in {@code serializedPrivateKey}.
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
   * Creates a new primitive for the key given in {@code proto}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code type_url}, and calls {@link
   * KeyManager#getPrimitive} with {@code key} as the parameter.
   *
   * @return a new primitive
   * @deprecated Use {@code getPrimitive(typeUrl, serializedKey, P.class)} instead.
   */
  @SuppressWarnings("TypeParameterUnusedInFormals")
  @Deprecated
  public static <P> P getPrimitive(String typeUrl, MessageLite key)
      throws GeneralSecurityException {
    KeyManager<P> manager = getKeyManager(typeUrl);
    return manager.getPrimitive(key.toByteString());
  }

  /**
   * Creates a new primitive for the key given in {@code key}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code type_url}, and calls {@link
   * KeyManager#getPrimitive} with {@code key} as the parameter.
   *
   * @return a new primitive
   * @deprecated Use {@code getPrimitive(typeUrl, serializedKey, Primitive.class} instead.
   */
  @Deprecated
  public static <P> P getPrimitive(
      String typeUrl, MessageLite key, Class<P> primitiveClass) throws GeneralSecurityException {
    KeyManager<P> manager = keyManagerRegistry.get().getKeyManager(typeUrl, primitiveClass);
    return manager.getPrimitive(key.toByteString());
  }

  /**
   * Creates a new primitive for the key given in {@code proto}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code type_url}, and calls {@link
   * KeyManager#getPrimitive} with {@code serializedKey} as the parameter.
   *
   * @return a new primitive
   * @deprecated Use {@code getPrimitive(typeUrl, serializedKey, Primitive.class} instead.
   */
  @SuppressWarnings("TypeParameterUnusedInFormals")
  @Deprecated
  public static <P> P getPrimitive(String typeUrl, ByteString serializedKey)
      throws GeneralSecurityException {
    KeyManager<P> manager = getKeyManager(typeUrl);
    return manager.getPrimitive(serializedKey);
  }

  /**
   * Creates a new primitive for the key given in {@code serializedKey}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code type_url}, and calls {@link
   * KeyManager#getPrimitive} with {@code serialized} as the parameter.
   *
   * @return a new primitive
   */
  public static <P> P getPrimitive(
      String typeUrl, ByteString serializedKey, Class<P> primitiveClass)
      throws GeneralSecurityException {
    KeyManager<P> manager = keyManagerRegistry.get().getKeyManager(typeUrl, primitiveClass);
    return manager.getPrimitive(serializedKey);
  }

  /**
   * Creates a new primitive for the key given in {@code serializedKey}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code type_url}, and calls {@link
   * KeyManager#getPrimitive} with {@code serialized} as the parameter.
   *
   * @deprecated Use {@code getPrimitive(typeUrl, serializedKey, Primitive.class)} instead.
   * @return a new primitive
   */
  @SuppressWarnings("TypeParameterUnusedInFormals")
  @Deprecated
  public static <P> P getPrimitive(String typeUrl, byte[] serializedKey)
      throws GeneralSecurityException {
    return getPrimitive(typeUrl, ByteString.copyFrom(serializedKey));
  }

  /**
   * Creates a new primitive for the key given in {@code serializedKey}.
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
   * Creates a new primitive for the key given in {@code keyData}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code keyData.type_url}, and calls {@link
   * KeyManager#getPrimitive} with {@code keyData.value} as the parameter.
   *
   * @return a new primitive
   * @deprecated Use {@code getPrimitive(keyData, Primitive.class)} instead.
   */
  @SuppressWarnings("TypeParameterUnusedInFormals")
  @Deprecated
  public static <P> P getPrimitive(KeyData keyData) throws GeneralSecurityException {
    return getPrimitive(keyData.getTypeUrl(), keyData.getValue());
  }

  /**
   * Creates a new primitive for the key given in {@code keyData}.
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

  static <KeyT extends Key, P> P getFullPrimitive(KeyT key, Class<P> primitiveClass)
      throws GeneralSecurityException {
    return MutablePrimitiveRegistry.globalInstance().getPrimitive(key, primitiveClass);
  }

  /**
   * Looks up the globally registered PrimitiveWrapper for this primitive and wraps the given
   * PrimitiveSet with it.
   */
  public static <B, P> P wrap(PrimitiveSet<B> primitiveSet, Class<P> clazz)
      throws GeneralSecurityException {
    return MutablePrimitiveRegistry.globalInstance().wrap(primitiveSet, clazz);
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
    return MutableParametersRegistry.globalInstance().getNames();
  }

  /**
   * Returns the input primitive required when creating a {@code wrappedPrimitive}.
   *
   * <p>This returns the primitive class of the objects required when we want to create a wrapped
   * primitive of type {@code wrappedPrimitive}. Returns {@code null} if no wrapper for this
   * primitive has been registered.
   */
  @Nullable
  public static Class<?> getInputPrimitive(Class<?> wrappedPrimitive) {
    try {
      return MutablePrimitiveRegistry.globalInstance().getInputPrimitiveClass(wrappedPrimitive);
    } catch (GeneralSecurityException e) {
      return null;
    }
  }

  /**
   * Tries to enable the FIPS restrictions if the Registry is empty.
   *
   * @throws GeneralSecurityException if any key manager has already been registered.
   */
  public static synchronized void restrictToFipsIfEmpty() throws GeneralSecurityException {
    // If we are already using FIPS mode, do nothing.
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    if (keyManagerRegistry.get().isEmpty()) {
      TinkFipsUtil.setFipsRestricted();
      return;
    }
    throw new GeneralSecurityException("Could not enable FIPS mode as Registry is not empty.");
  }

  private Registry() {}
}
