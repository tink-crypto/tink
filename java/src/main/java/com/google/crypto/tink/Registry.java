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

/**
 * Registry for KeyMangers. <p>
 * It is essentially a big container (map) that for each supported key type holds
 * a corresponding KeyManager object, which "understands" the key type (i.e. the KeyManager
 * can instantiate the primitive corresponding to given key, or can generate new keys
 * of the supported key type).  Registry is initialized at startup, and is later
 * used to instantiate primitives for given keys or keysets.  Keeping KeyManagers for all
 * primitives in a single Registry (rather than having a separate KeyManager per primitive)
 * enables modular construction of compound primitives from "simple" ones, e.g.,
 * AES-CTR-HMAC AEAD encryption uses IND-CPA encryption and a MAC. <p>
 *
 * Note that regular users will usually not work directly with Registry, but rather
 * via primitive factories, which in the background query the Registry for specific
 * KeyManagers.  Registry is public though, to enable configurations with custom
 * primitives and KeyManagers.
 */
public final class Registry {
  public static final Registry INSTANCE = new Registry();  // Default registry used by factories.

  @SuppressWarnings("rawtypes")
  private final ConcurrentMap<String, KeyManager> keyManager =
      new ConcurrentHashMap<String, KeyManager>();         // typeUrl -> KeyManager mapping


  /**
   * Creates an empty registry.
   */
  protected Registry() {}

  /**
   * Registers {@code manager} for the given {@code typeUrl}, assuming that there is
   * no key manager registered for {@code typeUrl} yet. Does nothing if there already exists
   * a key manager for {@code typeUrl}.
   *
   * @throws NullPointerException if {@code manager} is null.
   * @return true if the {@code manager} is registered as a manager for {@code typeUrl}; false if
   * there already exists a key manager for {@code typeUrl}.
   */
  @SuppressWarnings("unchecked")
  public <P> boolean registerKeyManager(String typeUrl, final KeyManager<P> manager)
      throws GeneralSecurityException {
    if (manager == null) {
      throw new NullPointerException("key manager must be non-null.");
    }
    KeyManager<P> existing = keyManager.putIfAbsent(typeUrl, manager);
    if (existing == null) {
      return true;
    }
    return false;
  }

  /**
   * @return a KeyManager for the given {@code typeUrl} (if found).
   *
   * TODO(przydatek): find a way for verifying the primitive type.
   */
  @SuppressWarnings("unchecked")
  public <P> KeyManager<P> getKeyManager(String typeUrl) throws GeneralSecurityException {
    KeyManager<P> manager = keyManager.get(typeUrl);
    if (manager == null) {
      throw new GeneralSecurityException("unsupported key type: " + typeUrl);
    }
    return manager;
  }

  /**
   * Convenience method for generating a new {@code KeyData} for the specified
   * {@code template}.
   * It looks up a KeyManager identified by {@code template.type_url}, and calls
   * managers {@code newKeyData(template)}-method.
   * This method should be used solely for key management.
   * @return a new key.
   */
  public <P> KeyData newKeyData(KeyTemplate template) throws GeneralSecurityException {
    KeyManager<P> manager = getKeyManager(template.getTypeUrl());
    return manager.newKeyData(template.getValue());
  }

  /**
   * Convenience method for generating a new key for the specified {@code keyTemplate}.
   * It looks up a KeyManager identified by {@code keyTemplate.typeUrl}, and calls
   * managers {@code newKey(keyTemplate.value)}-method.
   *
   * @return a new key.
   */
  public <P> MessageLite newKey(KeyTemplate keyTemplate) throws GeneralSecurityException {
    KeyManager<P> manager = getKeyManager(keyTemplate.getTypeUrl());
    return manager.newKey(keyTemplate.getValue());
  }

  /**
   * Convenience method for generating a new key for the specified {@code format}.
   * It looks up a KeyManager identified by {@code typeUrl}, and calls
   * managers {@code newKey(format)}-method.
   *
   * @return a new key.
   */
  public <P> MessageLite newKey(String typeUrl, MessageLite format)
      throws GeneralSecurityException {
    KeyManager<P> manager = getKeyManager(typeUrl);
    return manager.newKey(format);
  }

  /**
   * Convenience method for extracting the public key data from the private key given
   * in {@code serializedPrivateKey}.
   * It looks up a {@code PrivateKeyManager} identified by {@code typeUrl}, and calls
   * the manager's {@code getPublicKeyData(serializedPrivateKey)}-method.
   *
   * @return a new key.
   */
  @SuppressWarnings("unchecked")
  public <P> KeyData getPublicKeyData(String typeUrl, ByteString serializedPrivateKey)
      throws GeneralSecurityException {
    PrivateKeyManager<P> manager = (PrivateKeyManager) getKeyManager(typeUrl);
    return manager.getPublicKeyData(serializedPrivateKey);
  }

  /**
   * Convenience method for creating a new primitive for the key given in {@code proto}.
   * It looks up a KeyManager identified by {@code type_url}, and calls
   * managers {@code getPrimitive(proto)}-method.
   *
   * @return a new primitive.
   */
  @SuppressWarnings("TypeParameterUnusedInFormals")
  public <P> P getPrimitive(String typeUrl, MessageLite key) throws GeneralSecurityException {
    KeyManager<P> manager = getKeyManager(typeUrl);
    return manager.getPrimitive(key);
  }

  /**
   * Convenience method for creating a new primitive for the key given in {@code serialized}.
   * It looks up a KeyManager identified by {@code type_url}, and calls
   * managers {@code getPrimitive(serialized)}-method.
   *
   * @return a new primitive.
   */
  @SuppressWarnings("TypeParameterUnusedInFormals")
  public <P> P getPrimitive(String typeUrl, ByteString serialized)
      throws GeneralSecurityException {
    KeyManager<P> manager = getKeyManager(typeUrl);
    return manager.getPrimitive(serialized);
  }

  /**
   * Convenience method for creating a new primitive for the key given in {@code serialized}.
   * It looks up a KeyManager identified by {@code type_url}, and calls
   * managers {@code getPrimitive(serialized)}-method.
   *
   * @return a new primitive.
   */
  @SuppressWarnings("TypeParameterUnusedInFormals")
  public <P> P getPrimitive(String typeUrl, byte[] serialized) throws GeneralSecurityException {
    return getPrimitive(typeUrl, ByteString.copyFrom(serialized));
  }

  /**
   * Convenience method for creating a new primitive for the key given in {@code keyData}.
   * It looks up a KeyManager identified by {@code keyData.type_url}, and calls
   * managers {@code getPrimitive(keyData.value)}-method.
   *
   * @return a new primitive.
   */
  @SuppressWarnings("TypeParameterUnusedInFormals")
  public <P> P getPrimitive(KeyData keyData) throws GeneralSecurityException {
    return getPrimitive(keyData.getTypeUrl(), keyData.getValue());
  }

  /**
   * Creates a set of primitives corresponding to the keys with status=ENABLED in the keyset
   * given in {@code keysetHandle}, assuming all the corresponding key managers are present
   * (keys with status!=ENABLED are skipped).
   *
   * The returned set is usually later "wrapped" into a class that implements
   * the corresponding Primitive-interface.
   *
   * @return a PrimitiveSet with all instantiated primitives.
   */
  public <P> PrimitiveSet<P> getPrimitives(KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    return getPrimitives(keysetHandle, /* customManager= */null);
  }
  /**
   * Creates a set of primitives corresponding to the keys with status=ENABLED in the keyset
   * given in {@code keysetHandle}, using {@code customManager} (instead of registered
   * key managers) for keys supported by it.  Keys not supported by {@code customManager}
   * are handled by matching registered key managers (if present), and keys with status!=ENABLED
   * are skipped. <p>
   *
   * This enables custom treatment of keys, for example providing extra context (e.g. credentials
   * for accessing keys managed by a KMS), or gathering custom monitoring/profiling information.
   *
   * The returned set is usually later "wrapped" into a class that implements
   * the corresponding Primitive-interface.
   *
   * @return a PrimitiveSet with all instantiated primitives.
   */
    public <P> PrimitiveSet<P> getPrimitives(
        KeysetHandle keysetHandle, final KeyManager<P> customManager)
        throws GeneralSecurityException {
      Util.validateKeyset(keysetHandle.getKeyset());
      PrimitiveSet<P> primitives = PrimitiveSet.newPrimitiveSet();
      for (Keyset.Key key : keysetHandle.getKeyset().getKeyList()) {
        if (key.getStatus() == KeyStatusType.ENABLED) {
          P primitive;
          if (customManager != null && customManager.doesSupport(key.getKeyData().getTypeUrl())) {
            primitive = customManager.getPrimitive(key.getKeyData().getValue());
          } else {
            primitive = getPrimitive(key.getKeyData().getTypeUrl(),
                key.getKeyData().getValue());
          }
          PrimitiveSet.Entry<P> entry = primitives.addPrimitive(primitive, key);
          if (key.getKeyId() == keysetHandle.getKeyset().getPrimaryKeyId()) {
            primitives.setPrimary(entry);
          }
        }
      }
      return primitives;
  }
}
