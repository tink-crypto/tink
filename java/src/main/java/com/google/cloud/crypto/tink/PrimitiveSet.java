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

import com.google.cloud.crypto.tink.TinkProto.Keyset;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * A container class for a set of primitives (i.e. implementations of cryptographic
 * primitives offered by Tink).  It provides also additional properties for the primitives
 * it holds.  In particular, one of the primitives in the set can be distinguished as
 * "the primary" one. <p>
 *
 * PrimitiveSet is an auxiliary class used for supporting key rotation: primitives in a set
 * correspond to keys in a keyset.  Users will usually work with primitive instances,
 * which essentially wrap primitive sets.  For example an instance of an Aead-primitive
 * for a given keyset holds a set of Aead-primitivies corresponding to the keys in the keyset,
 * and uses the set members to do the actual crypto operations: to encrypt data the primary
 * Aead-primitive from the set is used, and upon decryption the ciphertext's prefix
 * determines the id of the primitive from the set. <p>
 *
 * PrimitiveSet is a public class to allow its use in implementations of custom primitives.
 */
public class PrimitiveSet<P> {
  /**
   * A single entry in the set. In addition to the actual primitive it holds also
   * some extra information about the primitive.
   * TODO(przydatek): update identifier to fit the key management mechanisms.
   */
  public class Entry<P> {
    private final P primitive;      // the actual primitive
    private final long identifier;  // identifies the primitive within the set
    private final Keyset.KeyStatus status;  // the status of the key represented by the primitive

    public Entry(P primitive, long identifier, Keyset.KeyStatus status) {
      this.primitive = primitive;
      this.identifier = identifier;
      this.status = status;
    }
    protected P getPrimitive() {
      return this.primitive;
    }
    protected Keyset.KeyStatus getStatus() {
      return status;
    }
    protected final long getIdentifier() {
      return identifier;
    }
  }

  protected static <P> PrimitiveSet<P> newPrimitiveSet() {
    return new PrimitiveSet<P>();
  }

  private ConcurrentMap<java.lang.Long, Entry<P>> primitives =
    new ConcurrentHashMap<java.lang.Long, Entry<P>>();

  private Entry<P> primary;

  /**
   * @returns the number of primitives in this set.
   */
  protected int size() {
    return primitives.size();
  }

  /**
   * @returns the entry with primitve identifed by {@code identifier}.
   * TODO(przydatek): make it return List<Entry<P>> to be able to handle identifier collisions.
   */
  protected Entry<P> getPrimitiveForId(long identifier) {
    return primitives.get(identifier);
  }

  /**
   * @returns the entry with the primary primitive.
   */
  protected Entry<P> getPrimary() {
    return primary;
  }

  /**
   * @returns sets given Entry {@code primary} as the primary one.
   */
  protected void setPrimary(Entry<P> primary) {
    this.primary = primary;
  }

  /**
   * Creates an entry in the primitive table.
   */
  protected void addPrimitive(P primitive, Keyset.Key key) {
    Entry<P> entry = new Entry<P>(primitive, key.getKeyId(), key.getStatus());
    primitives.put(new Long(key.getKeyId()), entry);
  }
}
