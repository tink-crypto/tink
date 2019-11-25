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

import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * A container class for a set of primitives -- implementations of cryptographic primitives offered
 * by Tink.
 *
 * <p>It provides also additional properties for the primitives it holds. In particular, one of the
 * primitives in the set can be distinguished as "the primary" one.
 *
 * <p>PrimitiveSet is an auxiliary class used for supporting key rotation: primitives in a set
 * correspond to keys in a keyset. Users will usually work with primitive instances, which
 * essentially wrap primitive sets. For example an instance of an Aead-primitive for a given keyset
 * holds a set of Aead-primitives corresponding to the keys in the keyset, and uses the set members
 * to do the actual crypto operations: to encrypt data the primary Aead-primitive from the set is
 * used, and upon decryption the ciphertext's prefix determines the id of the primitive from the
 * set.
 *
 * <p>PrimitiveSet is a public class to allow its use in implementations of custom primitives.
 *
 * @since 1.0.0
 */
public final class PrimitiveSet<P> {
  private static final Charset UTF_8 = Charset.forName("UTF-8");
  /**
   * A single entry in the set. In addition to the actual primitive it holds also some extra
   * information about the primitive.
   */
  public static final class Entry<P> {
    // The actual primitive.
    private final P primitive;
    // Identifies the primitive within the set.
    // It is the ciphertext prefix of the corresponding key.
    private final byte[] identifier;
    // The status of the key represented by the primitive.
    private final KeyStatusType status;
    // The output prefix type of the key represented by the primitive.
    private final OutputPrefixType outputPrefixType;
    // The id of the key.
    private final int keyId;

    Entry(
        P primitive,
        final byte[] identifier,
        KeyStatusType status,
        OutputPrefixType outputPrefixType,
        int keyId) {
      this.primitive = primitive;
      this.identifier = Arrays.copyOf(identifier, identifier.length);
      this.status = status;
      this.outputPrefixType = outputPrefixType;
      this.keyId = keyId;
    }

    public P getPrimitive() {
      return this.primitive;
    }

    public KeyStatusType getStatus() {
      return status;
    }

    public OutputPrefixType getOutputPrefixType() {
      return outputPrefixType;
    }

    public final byte[] getIdentifier() {
      if (identifier == null) {
        return null;
      } else {
        return Arrays.copyOf(identifier, identifier.length);
      }
    }

    public int getKeyId() {
      return keyId;
    }
  }

  /** @return the entry with the primary primitive. */
  public Entry<P> getPrimary() {
    return primary;
  }

  /** @return all primitives using RAW prefix. */
  public List<Entry<P>> getRawPrimitives() {
    return getPrimitive(CryptoFormat.RAW_PREFIX);
  }

  /** @return the entries with primitive identifed by {@code identifier}. */
  public List<Entry<P>> getPrimitive(final byte[] identifier) {
    List<Entry<P>> found = primitives.get(new String(identifier, UTF_8));
    return found != null ? found : Collections.<Entry<P>>emptyList();
  }

  /** Returns the entries with primitives identified by the ciphertext prefix of {@code key}. */
  protected List<Entry<P>> getPrimitive(Keyset.Key key) throws GeneralSecurityException {
    return getPrimitive(CryptoFormat.getOutputPrefix(key));
  }

  /** @return all primitives */
  public Collection<List<Entry<P>>> getAll() {
    return primitives.values();
  }

  /**
   * The primitives are stored in a hash map of (ciphertext prefix, list of primivies sharing the
   * prefix). This allows quickly retrieving the list of primitives sharing some particular prefix.
   * Because all RAW keys are using an empty prefix, this also quickly allows retrieving them.
   */
  private ConcurrentMap<java.lang.String, List<Entry<P>>> primitives =
      new ConcurrentHashMap<java.lang.String, List<Entry<P>>>();

  private Entry<P> primary;
  private final Class<P> primitiveClass;

  private PrimitiveSet(Class<P> primitiveClass) {
    this.primitiveClass = primitiveClass;
  }

  public static <P> PrimitiveSet<P> newPrimitiveSet(Class<P> primitiveClass) {
    return new PrimitiveSet<P>(primitiveClass);
  }

  /** Sets given Entry {@code primary} as the primary one. */
  public void setPrimary(final Entry<P> primary) {
    if (primary == null) {
      throw new IllegalArgumentException("the primary entry must be non-null");
    }
    if (primary.getStatus() != KeyStatusType.ENABLED) {
      throw new IllegalArgumentException("the primary entry has to be ENABLED");
    }
    List<Entry<P>> entries = getPrimitive(primary.getIdentifier());
    if (entries.isEmpty()) {
      throw new IllegalArgumentException(
          "the primary entry cannot be set to an entry which is not held by this primitive set");
    }
    this.primary = primary;
  }

  /**
   * Creates an entry in the primitive table.
   *
   * @return the added entry
   */
  public Entry<P> addPrimitive(final P primitive, Keyset.Key key)
      throws GeneralSecurityException {
    if (key.getStatus() != KeyStatusType.ENABLED) {
      throw new GeneralSecurityException("only ENABLED key is allowed");
    }
    Entry<P> entry =
        new Entry<P>(
            primitive,
            CryptoFormat.getOutputPrefix(key),
            key.getStatus(),
            key.getOutputPrefixType(),
            key.getKeyId());
    List<Entry<P>> list = new ArrayList<Entry<P>>();
    list.add(entry);
    // Cannot use [] as keys in hash map, convert to string.
    String identifier = new String(entry.getIdentifier(), UTF_8);
    List<Entry<P>> existing = primitives.put(identifier, Collections.unmodifiableList(list));
    if (existing != null) {
      List<Entry<P>> newList = new ArrayList<Entry<P>>();
      newList.addAll(existing);
      newList.add(entry);
      primitives.put(identifier, Collections.unmodifiableList(newList));
    }
    return entry;
  }

  public Class<P> getPrimitiveClass() {
    return primitiveClass;
  }
}
