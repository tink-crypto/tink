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

package com.google.cloud.crypto.tink;

import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key;
import com.google.protobuf.Any;
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
   * @returns true if the {@code manager} is registered as a manager for {@code typeUrl}; false if
   * there already exists a key manager for {@code typeUrl}.
   */
  @SuppressWarnings("unchecked")
  public <P> boolean registerKeyManager(String typeUrl, final KeyManager<P> manager)
      throws GeneralSecurityException {
    if (manager == null) {
      throw new NullPointerException("Key manager must be non-null.");
    }
    KeyManager<P> existing = keyManager.putIfAbsent(typeUrl, manager);
    if (existing == null) {
      return true;
    }
    return false;
  }

  /**
   * @returns a KeyManager for the given {@code typeUrl} (if found).
   *
   * TODO(przydatek): find a way for verifying the primitive type.
   */
  @SuppressWarnings("unchecked")
  public <P> KeyManager<P> getKeyManager(String typeUrl)
      throws GeneralSecurityException {
    KeyManager<P> manager = keyManager.get(typeUrl);
    if (manager == null) {
      throw new GeneralSecurityException("Unsupported key type: " + typeUrl);
    }
    return manager;
  }

  /**
   * Convenience method for generating a new key for the specified {@code format}.
   * It looks up a KeyManager identified by {@code format.key_type}, and calls
   * managers {@code newKey(format)}-method.
   *
   * @returns a new key.
   */
  public <P> Any newKey(KeyFormat format)
      throws GeneralSecurityException {
    KeyManager<P> manager = getKeyManager(format.getKeyType());
    return manager.newKey(format);
  }

  /**
   * Convenience method for creating a new primitive for the key given in {@code proto}.
   * It looks up a KeyManager identified by {@code proto.type_url}, and calls
   * managers {@code getPrimitive(proto)}-method.
   *
   * @returns a new primitive.
   */
  public <P> P getPrimitive(Any proto)
      throws GeneralSecurityException {
    KeyManager<P> manager = getKeyManager(proto.getTypeUrl());
    return manager.getPrimitive(proto);
  }

  /**
   * Creates a set of primitives corresponding to the keys with status=ENABLED in the keyset
   * given in {@code keysetHandle}, assuming all the corresponding key managers are present
   * (keys with status!=ENABLED are skipped).
   *
   * The returned set is usually later "wrapped" into a class that implements
   * the corresponding Primitive-interface.
   *
   * @returns a PrimitiveSet with all instantiated primitives.
   */
  public <P> PrimitiveSet<P> getPrimitives(final KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    return getPrimitives(keysetHandle, null /* customManager */);
  }
  /**
   * Creates a set of primitives corresponding to the keys with status=ENABLED in the keyset
   * given in {@code keysetHandle}, using {@code customManager} (instead of registered key managers)
   * for keys supported by it.  Keys not supported by {@code customManager} are handled by matching
   * registered key managers (if present), and keys with status!=ENABLED are skipped. <p>
   *
   * This enables custom treatment of keys, for example providing extra context (e.g. credentials
   * for accessing keys managed by a KMS), or gathering custom monitoring/profiling information.
   *
   * The returned set is usually later "wrapped" into a class that implements
   * the corresponding Primitive-interface.
   *
   * @returns a PrimitiveSet with all instantiated primitives.
   */
    public <P> PrimitiveSet<P> getPrimitives(final KeysetHandle keysetHandle,
        final KeyManager<P> customManager) throws GeneralSecurityException {
    PrimitiveSet<P> primitives = PrimitiveSet.newPrimitiveSet();
    for (Keyset.Key key : keysetHandle.getKeyset().getKeyList()) {
      if (key.getStatus() == KeyStatusType.ENABLED) {
        P primitive;
        if (customManager != null && customManager.doesSupport(key.getKeyData().getTypeUrl())) {
          primitive = customManager.getPrimitive(key.getKeyData());
        } else {
          primitive = getPrimitive(key.getKeyData());
        }
        PrimitiveSet<P>.Entry<P> entry = primitives.addPrimitive(primitive, key);
        if (key.getKeyId() == keysetHandle.getKeyset().getPrimaryKeyId()) {
          primitives.setPrimary(entry);
        }
      }
    }
    return primitives;
  }

}
