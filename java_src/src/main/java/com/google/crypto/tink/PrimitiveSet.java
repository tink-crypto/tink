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

import com.google.crypto.tink.annotations.Alpha;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Hex;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import javax.annotation.Nullable;

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

  // A simple implementation of Parameters.
  // Consider renaming this class and moving it into internal. And use it in LegacyProtoKey.
  @Immutable
  @Alpha
  private static class SimpleParameters extends Parameters {

    private final String typeUrl;
    private final OutputPrefixType outputPrefixType;

    @Override
    public boolean hasIdRequirement() {
      return outputPrefixType != OutputPrefixType.RAW;
    }

    // This function is needed because LiteProto do not have a good toString function.
    private static String outputPrefixToString(OutputPrefixType outputPrefixType) {
      switch (outputPrefixType) {
        case TINK:
          return "TINK";
        case LEGACY:
          return "LEGACY";
        case RAW:
          return "RAW";
        case CRUNCHY:
          return "CRUNCHY";
        default:
          return "UNKNOWN";
      }
    }

    /**
     * Returns the string representation. The exact details are unspecified and subject to change.
     */
    @Override
    public String toString() {
      return String.format(
          "(typeUrl=%s, outputPrefixType=%s)", typeUrl, outputPrefixToString(outputPrefixType));
    }

    private SimpleParameters(String typeUrl, OutputPrefixType outputPrefixType) {
      this.typeUrl = typeUrl;
      this.outputPrefixType = outputPrefixType;
    }
  }

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
    private final Parameters parameters;

    Entry(
        P primitive,
        final byte[] identifier,
        KeyStatusType status,
        OutputPrefixType outputPrefixType,
        int keyId,
        Parameters parameters) {
      this.primitive = primitive;
      this.identifier = Arrays.copyOf(identifier, identifier.length);
      this.status = status;
      this.outputPrefixType = outputPrefixType;
      this.keyId = keyId;
      this.parameters = parameters;
    }

    /**
     * Returns the primitive for this entry.
     *
     * <p>For primitives of type {@code Mac}, {@code Aead}, {@code PublicKeySign}, {@code
     * PublicKeyVerify}, {@code DeterministicAead}, {@code HybridEncrypt}, and {@code HybridDecrypt}
     * this is a primitive which <b>ignores</b> the output prefix and assumes "RAW".
     */
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

    public Parameters getParameters() {
      return parameters;
    }
  }

  /** @return the entry with the primary primitive. */
  @Nullable
  public Entry<P> getPrimary() {
    return primary;
  }

  public boolean hasAnnotations() {
    return !annotations.toMap().isEmpty();
  }

  public MonitoringAnnotations getAnnotations() {
    return annotations;
  }

  /** @return all primitives using RAW prefix. */
  public List<Entry<P>> getRawPrimitives() {
    return getPrimitive(CryptoFormat.RAW_PREFIX);
  }

  /** @return the entries with primitive identifed by {@code identifier}. */
  public List<Entry<P>> getPrimitive(final byte[] identifier) {
    List<Entry<P>> found = primitives.get(new Prefix(identifier));
    return found != null ? found : Collections.<Entry<P>>emptyList();
  }

  /** Returns the entries with primitives identified by the ciphertext prefix of {@code key}. */
  List<Entry<P>> getPrimitive(Keyset.Key key) throws GeneralSecurityException {
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
  private final ConcurrentMap<Prefix, List<Entry<P>>> primitives;

  private Entry<P> primary;
  private final Class<P> primitiveClass;
  private final MonitoringAnnotations annotations;
  private final boolean isMutable;

  @Deprecated
  private PrimitiveSet(Class<P> primitiveClass) {
    this.primitives = new ConcurrentHashMap<>();
    this.primitiveClass = primitiveClass;
    this.annotations = MonitoringAnnotations.EMPTY;
    this.isMutable = true;
  }

  /** Creates an immutable PrimitiveSet. It is used by the Builder.*/
  private PrimitiveSet(ConcurrentMap<Prefix, List<Entry<P>>> primitives,
      Entry<P> primary, MonitoringAnnotations annotations, Class<P> primitiveClass) {
    this.primitives = primitives;
    this.primary = primary;
    this.primitiveClass = primitiveClass;
    this.annotations = annotations;
    this.isMutable = false;
  }

  /**
   * Creates a new mutable PrimitiveSet.
   *
   * @deprecated use {@link Builder} instead.
   */
  @Deprecated
  public static <P> PrimitiveSet<P> newPrimitiveSet(Class<P> primitiveClass) {
    return new PrimitiveSet<P>(primitiveClass);
  }

  /** Sets given Entry {@code primary} as the primary one.
   *
   * @throws IllegalStateException if object has been created by the {@link Builder}.
   * @deprecated use {@link Builder.addPrimaryPrimitive} instead.
   */
  @Deprecated
  public void setPrimary(final Entry<P> primary) {
    if (!isMutable) {
      throw new IllegalStateException("setPrimary cannot be called on an immutable primitive set");
    }
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
   * @return the added {@link Entry}
   *
   * @throws IllegalStateException if object has been created by the {@link Builder}.
   * @deprecated use {@link Builder.addPrimitive} or {@link Builder.addPrimaryPrimitive} instead.
   */
  @Deprecated
  public Entry<P> addPrimitive(final P primitive, Keyset.Key key)
      throws GeneralSecurityException {
    if (!isMutable) {
      throw new IllegalStateException(
          "addPrimitive cannot be called on an immutable primitive set");
    }
    if (key.getStatus() != KeyStatusType.ENABLED) {
      throw new GeneralSecurityException("only ENABLED key is allowed");
    }
    Parameters parameters =
        new SimpleParameters(key.getKeyData().getTypeUrl(), key.getOutputPrefixType());
    Entry<P> entry =
        new Entry<P>(
            primitive,
            CryptoFormat.getOutputPrefix(key),
            key.getStatus(),
            key.getOutputPrefixType(),
            key.getKeyId(),
            parameters);
    List<Entry<P>> list = new ArrayList<>();
    list.add(entry);
    // Cannot use byte[] as keys in hash map, convert to Prefix wrapper class.
    Prefix identifier = new Prefix(entry.getIdentifier());
    List<Entry<P>> existing = primitives.put(identifier, Collections.unmodifiableList(list));
    if (existing != null) {
      List<Entry<P>> newList = new ArrayList<>();
      newList.addAll(existing);
      newList.add(entry);
      primitives.put(identifier, Collections.unmodifiableList(newList));
    }
    return entry;
  }

  public Class<P> getPrimitiveClass() {
    return primitiveClass;
  }

  private static class Prefix implements Comparable<Prefix> {
    private final byte[] prefix;

    private Prefix(byte[] prefix) {
      this.prefix = Arrays.copyOf(prefix, prefix.length);
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(prefix);
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof Prefix)) {
        return false;
      }
      Prefix other = (Prefix) o;
      return Arrays.equals(prefix, other.prefix);
    }

    @Override
    public int compareTo(Prefix o) {
      if (prefix.length != o.prefix.length) {
        return prefix.length - o.prefix.length;
      }
      for (int i = 0; i < prefix.length; i++) {
        if (prefix[i] != o.prefix[i]) {
          return prefix[i] - o.prefix[i];
        }
      }
      return 0;
    }

    @Override
    public String toString() {
      return Hex.encode(prefix);
    }
  }

  /** Builds an immutable PrimitiveSet. This is the prefered way to construct a PrimitiveSet. */
  public static class Builder<P> {
    private final Class<P> primitiveClass;

    // primitives == null indicates that build has been called and the builder can't be used
    // anymore.
    private ConcurrentMap<Prefix, List<Entry<P>>> primitives = new ConcurrentHashMap<>();
    private Entry<P> primary;
    private MonitoringAnnotations annotations;

    private Builder<P> addPrimitive(final P primitive, Keyset.Key key, boolean asPrimary)
        throws GeneralSecurityException {
      if (primitives == null) {
        throw new IllegalStateException("addPrimitive cannot be called after build");
      }
      if (key.getStatus() != KeyStatusType.ENABLED) {
        throw new GeneralSecurityException("only ENABLED key is allowed");
      }
      Parameters parameters =
          new SimpleParameters(key.getKeyData().getTypeUrl(), key.getOutputPrefixType());
      Entry<P> entry =
          new Entry<P>(
              primitive,
              CryptoFormat.getOutputPrefix(key),
              key.getStatus(),
              key.getOutputPrefixType(),
              key.getKeyId(),
              parameters);
      List<Entry<P>> list = new ArrayList<>();
      list.add(entry);
      // Cannot use byte[] as keys in hash map, convert to Prefix wrapper class.
      Prefix identifier = new Prefix(entry.getIdentifier());
      List<Entry<P>> existing = primitives.put(identifier, Collections.unmodifiableList(list));
      if (existing != null) {
        List<Entry<P>> newList = new ArrayList<>();
        newList.addAll(existing);
        newList.add(entry);
        primitives.put(identifier, Collections.unmodifiableList(newList));
      }
      if (asPrimary) {
        if (this.primary != null) {
          throw new IllegalStateException("you cannot set two primary primitives");
        }
        this.primary = entry;
      }
      return this;
    }

    /* Adds a non-primary primitive.*/
    public Builder<P> addPrimitive(final P primitive, Keyset.Key key)
        throws GeneralSecurityException {
      return addPrimitive(primitive, key, false);
    }

    /* Adds the primary primitive. Should be called exactly once per PrimitiveSet.*/
    public Builder<P> addPrimaryPrimitive(final P primitive, Keyset.Key key)
        throws GeneralSecurityException {
      return addPrimitive(primitive, key, true);
    }

    public Builder<P> setAnnotations(MonitoringAnnotations annotations) {
      if (primitives == null) {
        throw new IllegalStateException("setAnnotations cannot be called after build");
      }
      this.annotations = annotations;
      return this;
    }

    public PrimitiveSet<P> build() throws GeneralSecurityException {
      if (primitives == null) {
        throw new IllegalStateException("build cannot be called twice");
      }
      // Note that we currently don't enforce that primary must be set.
      PrimitiveSet<P> output =
          new PrimitiveSet<P>(primitives, primary, annotations, primitiveClass);
      this.primitives = null;
      return output;
    }

    private Builder(Class<P> primitiveClass) {
      this.primitiveClass = primitiveClass;
      this.annotations = MonitoringAnnotations.EMPTY;
    }
  }

  public static <P> Builder<P> newBuilder(Class<P> primitiveClass) {
    return new Builder<P>(primitiveClass);
  }
}
