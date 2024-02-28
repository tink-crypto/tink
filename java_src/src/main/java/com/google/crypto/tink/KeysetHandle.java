// Copyright 2017 Google LLC
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
import com.google.crypto.tink.internal.InternalConfiguration;
import com.google.crypto.tink.internal.LegacyProtoParameters;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.PrimitiveSet;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.internal.RegistryConfiguration;
import com.google.crypto.tink.internal.TinkBugException;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.tinkkey.KeyAccess;
import com.google.crypto.tink.tinkkey.KeyHandle;
import com.google.crypto.tink.tinkkey.internal.InternalKeyHandle;
import com.google.crypto.tink.tinkkey.internal.ProtoKey;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nullable;

/**
 * A KeysetHandle provides abstracted access to {@link Keyset}, to limit the exposure of actual
 * protocol buffers that hold sensitive key material.
 *
 * <p>This class allows reading and writing encrypted keysets. Users that want to read or write can
 * use the restricted API {@link CleartextKeysetHandle}. Users can also load keysets that don't
 * contain any secret key material with {@link NoSecretKeysetHandle}.
 *
 * @since 1.0.0
 */
public final class KeysetHandle {
  /**
   * Used to create new {@code KeysetHandle} objects.
   *
   * <p>A builder can be used to create a new {@code KeysetHandle} object. To create a builder with
   * an empty keyset, one calls {@code KeysetHandle.newBuilder();}. To create a builder from an
   * existing keyset, one calls {@code KeysetHandle.newBuilder(keyset);}.
   *
   * <p>To add a new key to a {@code Builder}, one calls {@link #addEntry} with a KeysetEntry
   * object. Such objects can be created
   *
   * <ul>
   *   <li>From a named {@link Parameters} with {@link
   *       KeysetHandle#generateEntryFromParametersName},
   *   <li>From a {@link Parameters} object, with {@link KeysetHandle#generateEntryFromParameters},
   *   <li>By importing an existing key, with {@link KeysetHandle#importKey}
   * </ul>
   *
   * <p>All these functions return a {@code KeysetBuilder.Entry}. It is necessary to assign an ID to
   * a new entry by calling one of {@link Entry#withFixedId} or {@link Entry#withRandomId}. The
   * exception is when an existing key which has an id requirement is imported (in which case the
   * required ID is used).
   *
   * <p>It is possible to set the status of an entry by calling {@link Entry#setStatus}. The Status
   * defaults to {@code ENABLED}.
   *
   * <p>It is possible to set whether an entry is the primary by calling {@link Entry#makePrimary}.
   * The user must ensure that once {@link #build} is called, a primary has been set.
   */
  public static final class Builder {
    private static class KeyIdStrategy {
      private static final KeyIdStrategy RANDOM_ID = new KeyIdStrategy();
      private final int fixedId;

      private KeyIdStrategy() {
        this.fixedId = 0;
      }

      private KeyIdStrategy(int id) {
        this.fixedId = id;
      }

      private static KeyIdStrategy randomId() {
        return RANDOM_ID;
      }

      private static KeyIdStrategy fixedId(int id) {
        return new KeyIdStrategy(id);
      }

      private int getFixedId() {
        return fixedId;
      }
    }

    /**
     * One entry, representing a single key, in a Keyset.Builder.
     *
     * <p>This is the analogue of {@link Keyset.Entry} for a builder.
     *
     * <p>Users will have to ensure that each entry has an ID, and one entry is a primary. See
     * {@link KeysetHandle.Builder#build} for details).
     */
    public static final class Entry {
      // When "build" is called, for exactly one entry "isPrimary" needs to be set, and it should
      // be enabled.
      private boolean isPrimary;
      // Set to ENABLED by default.
      private KeyStatus keyStatus = KeyStatus.ENABLED;

      // Exactly one of key and parameters will be non-null (set in the constructor).
      @Nullable private final Key key;
      @Nullable private final Parameters parameters;
      // strategy must be non-null when the keyset is built.
      private KeyIdStrategy strategy = null;

      // The Builder which this Entry is part of. Each entry can be part of only one builder.
      // When constructing a new entry, it is not part of any builder.
      @Nullable private KeysetHandle.Builder builder = null;

      private Entry(Key key) {
        this.key = key;
        this.parameters = null;
      }

      private Entry(Parameters parameters) {
        this.key = null;
        this.parameters = parameters;
      }

      /**
       * Marks that this entry is the primary key.
       *
       * <p>Other entries in the same keyset will be marked as non-primary if this Entry has already
       * been added to a builder, otherwise they will marked as non-primary once this entry is added
       * to a builder.
       */
      @CanIgnoreReturnValue
      public Entry makePrimary() {
        if (builder != null) {
          builder.clearPrimary();
        }
        isPrimary = true;
        return this;
      }

      /** Returns whether this entry has been marked as a primary. */
      public boolean isPrimary() {
        return isPrimary;
      }

      /** Sets the status of this entry. */
      @CanIgnoreReturnValue
      public Entry setStatus(KeyStatus status) {
        keyStatus = status;
        return this;
      }

      /** Returns the status of this entry. */
      public KeyStatus getStatus() {
        return keyStatus;
      }

      /** Tells Tink to assign a fixed id when this keyset is built. */
      @CanIgnoreReturnValue
      public Entry withFixedId(int id) {
        this.strategy = KeyIdStrategy.fixedId(id);
        return this;
      }

      /**
       * Tells Tink to assign an unused uniform random id when this keyset is built.
       *
       * <p>Using {@code withRandomId} is invalid for an entry with an imported or preexisting key,
       * which has an ID requirement.
       *
       * <p>If an entry is marked as {@code withRandomId}, all subsequent entries also need to be
       * marked with {@code withRandomId}, or else calling {@code build()} will fail.
       */
      @CanIgnoreReturnValue
      public Entry withRandomId() {
        this.strategy = KeyIdStrategy.randomId();
        return this;
      }
    }

    private final List<KeysetHandle.Builder.Entry> entries = new ArrayList<>();
    // If set, throw this error on BUILD instead of actually building.
    @Nullable private GeneralSecurityException errorToThrow = null;
    private MonitoringAnnotations annotations = MonitoringAnnotations.EMPTY;
    private boolean buildCalled = false;

    private void clearPrimary() {
      for (Builder.Entry entry : entries) {
        entry.isPrimary = false;
      }
    }

    /** Adds an entry to a keyset */
    @CanIgnoreReturnValue
    public KeysetHandle.Builder addEntry(KeysetHandle.Builder.Entry entry) {
      if (entry.builder != null) {
        throw new IllegalStateException("Entry has already been added to a KeysetHandle.Builder");
      }
      if (entry.isPrimary) {
        clearPrimary();
      }
      entry.builder = this;
      entries.add(entry);
      return this;
    }

    /**
     * Sets MonitoringAnnotations. If not called, then the default value of {@link
     * MonitoringAnnotations.EMPTY} is used.
     *
     * <p>When called twice, the last submitted annotations are used to create the keyset. This
     * method is not thread-safe, and in case of multithreaded access it cannot be guaranteed which
     * annotations get set.
     */
    @CanIgnoreReturnValue
    @Alpha
    public KeysetHandle.Builder setMonitoringAnnotations(MonitoringAnnotations annotations) {
      this.annotations = annotations;
      return this;
    }

    /** Returns the number of entries in this builder. */
    public int size() {
      return entries.size();
    }

    /**
     * Returns the entry at index i, 0 <= i < size().
     *
     * @throws IndexOutOfBoundsException if i < 0 or i >= size();
     */
    public Builder.Entry getAt(int i) {
      return entries.get(i);
    }

    /**
     * Removes the entry at index {@code i} and returns that entry. Shifts any subsequent entries to
     * the left (subtracts one from their indices).
     *
     * @deprecated Use {@link #deleteAt} or {@link #getAt} instead.
     */
    @CanIgnoreReturnValue
    @Deprecated
    public Builder.Entry removeAt(int i) {
      return entries.remove(i);
    }

    /**
     * Deletes the entry at index {@code i}. Shifts any subsequent entries to the left (subtracts
     * one from their indices).
     */
    @CanIgnoreReturnValue
    public KeysetHandle.Builder deleteAt(int i) {
      entries.remove(i);
      return this;
    }

    private static void checkIdAssignments(List<KeysetHandle.Builder.Entry> entries)
        throws GeneralSecurityException {
      // We want "withRandomId"-entries after fixed id, as otherwise it might be that we randomly
      // pick a number which is later specified as "withFixedId". Looking forward is deemed too
      // complicated, especially if in the future we want different strategies (such as
      // "withNextId").
      for (int i = 0; i < entries.size() - 1; ++i) {
        if (entries.get(i).strategy == KeyIdStrategy.RANDOM_ID
            && entries.get(i + 1).strategy != KeyIdStrategy.RANDOM_ID) {
          throw new GeneralSecurityException(
              "Entries with 'withRandomId()' may only be followed by other entries with"
                  + " 'withRandomId()'.");
        }
      }
    }

    private void setErrorToThrow(GeneralSecurityException errorToThrow) {
      this.errorToThrow = errorToThrow;
    }

    private static int randomIdNotInSet(Set<Integer> ids) {
      int id = 0;
      while (id == 0 || ids.contains(id)) {
        id = com.google.crypto.tink.internal.Util.randKeyId();
      }
      return id;
    }

    private static Keyset.Key createNewKeysetKeyFromParameters(
        Parameters parameters, KeyStatus status, int id) throws GeneralSecurityException {
      ProtoParametersSerialization serializedParameters;
      if (parameters instanceof LegacyProtoParameters) {
        serializedParameters = ((LegacyProtoParameters) parameters).getSerialization();
      } else {
        serializedParameters =
            MutableSerializationRegistry.globalInstance()
                .serializeParameters(parameters, ProtoParametersSerialization.class);
      }
      KeyData keyData = Registry.newKeyData(serializedParameters.getKeyTemplate());
      return Keyset.Key.newBuilder()
          .setKeyId(id)
          .setStatus(serializeStatus(status))
          .setKeyData(keyData)
          .setOutputPrefixType(serializedParameters.getKeyTemplate().getOutputPrefixType())
          .build();
    }

    private static int getNextIdFromBuilderEntry(
        KeysetHandle.Builder.Entry builderEntry, Set<Integer> idsSoFar)
        throws GeneralSecurityException {
      int id = 0;
      if (builderEntry.strategy == null) {
        throw new GeneralSecurityException("No ID was set (with withFixedId or withRandomId)");
      }
      if (builderEntry.strategy == KeyIdStrategy.RANDOM_ID) {
        id = randomIdNotInSet(idsSoFar);
      } else {
        id = builderEntry.strategy.getFixedId();
      }
      return id;
    }

    /**
     * Creates a new {@code KeysetHandle}.
     *
     * <p>Throws a {@code GeneralSecurityException} if one of the following holds
     *
     * <ul>
     *   <li>No entry was marked as primary
     *   <li>There is an entry in which the ID has not been set and which did not have a predefined
     *       ID (see {@link Builder.Entry}).
     *   <li>There is a {@code withRandomId}-entry which is followed by a non {@code
     *       withRandomId}-entry
     *   <li>There are two entries with the same {@code withFixedId} (including pre-existing keys
     *       and imported keys which have an id requirement).
     *   <li>{@code build()} was previously called for {@code withRandomId} entries, and hence
     *       calling {@code build()} twice would result in a keyset with different key IDs.
     *   <li>The primary key is not enabled
     * </ul>
     */
    public KeysetHandle build() throws GeneralSecurityException {
      if (errorToThrow != null) {
        throw new GeneralSecurityException(
            "Cannot build keyset due to error in original", errorToThrow);
      }
      if (buildCalled) {
        throw new GeneralSecurityException("KeysetHandle.Builder#build must only be called once");
      }
      buildCalled = true;
      Keyset.Builder keysetBuilder = Keyset.newBuilder();
      List<KeysetHandle.Entry> handleEntries = new ArrayList<>(entries.size());
      Integer primaryId = null;

      checkIdAssignments(entries);
      Set<Integer> idsSoFar = new HashSet<>();
      for (KeysetHandle.Builder.Entry builderEntry : entries) {
        if (builderEntry.keyStatus == null) {
          throw new GeneralSecurityException("Key Status not set.");
        }
        int id = getNextIdFromBuilderEntry(builderEntry, idsSoFar);
        if (idsSoFar.contains(id)) {
          throw new GeneralSecurityException("Id " + id + " is used twice in the keyset");
        }
        idsSoFar.add(id);

        Keyset.Key keysetKey;
        @Nullable KeysetHandle.Entry handleEntry;

        if (builderEntry.key != null) {
          handleEntry =
              new KeysetHandle.Entry(
                  builderEntry.key, builderEntry.keyStatus, id, builderEntry.isPrimary);
          keysetKey = createKeysetKey(builderEntry.key, builderEntry.keyStatus, id);
        } else {
          keysetKey =
              createNewKeysetKeyFromParameters(builderEntry.parameters, builderEntry.keyStatus, id);
          try {
            Key key = toKey(keysetKey);
            handleEntry =
                new KeysetHandle.Entry(key, builderEntry.keyStatus, id, builderEntry.isPrimary);
          } catch (GeneralSecurityException e) {
            handleEntry = null;
          }
        }
        keysetBuilder.addKey(keysetKey);
        if (builderEntry.isPrimary) {
          if (primaryId != null) {
            throw new GeneralSecurityException("Two primaries were set");
          }
          primaryId = id;
          if (builderEntry.keyStatus != KeyStatus.ENABLED) {
            throw new GeneralSecurityException("Primary key is not enabled");
          }
        }
        handleEntries.add(handleEntry);
      }
      if (primaryId == null) {
        throw new GeneralSecurityException("No primary was set");
      }
      keysetBuilder.setPrimaryKeyId(primaryId);
      Keyset keyset = keysetBuilder.build();
      assertEnoughKeyMaterial(keyset);
      return new KeysetHandle(keyset, handleEntries, annotations);
    }
  }

  /**
   * Represents a single entry in a keyset.
   *
   * <p>An entry in a keyset consists of a key, its ID, and the {@link KeyStatus}. In addition,
   * there is one key marked as a primary.
   *
   * <p>The ID should be considered unique (though currently Tink still accepts keysets with
   * repeated IDs). The {@code KeyStatus} tells Tink whether the key should still be used or not.
   * There should always be exactly one key which is marked as a primary, however, at the moment
   * Tink still accepts keysets which have none. This will be changed in the future.
   */
  @Immutable
  public static final class Entry {
    private Entry(Key key, KeyStatus keyStatus, int id, boolean isPrimary) {
      this.key = key;
      this.keyStatus = keyStatus;
      this.id = id;
      this.isPrimary = isPrimary;
    }

    private final Key key;
    private final KeyStatus keyStatus;
    private final int id;
    private final boolean isPrimary;
    /**
     * May return an internal class {@link com.google.crypto.tink.internal.LegacyProtoKey} in case
     * there is no implementation of the corresponding key class yet.
     */
    public Key getKey() {
      return key;
    }

    public KeyStatus getStatus() {
      return keyStatus;
    }

    public int getId() {
      return id;
    }
    /**
     * Guaranteed to be true in exactly one entry.
     *
     * <p>Note: currently this may be false for all entries, since it is possible that keysets are
     * parsed without a primary. In the future, such keysets will be rejected when the keyset is
     * parsed.
     */
    public boolean isPrimary() {
      return isPrimary;
    }

    private boolean equalsEntry(Entry other) {
      if (other.isPrimary != isPrimary) {
        return false;
      }
      if (!other.keyStatus.equals(keyStatus)) {
        return false;
      }
      if (other.id != id) {
        return false;
      }
      if (!other.key.equalsKey(key)) {
        return false;
      }
      return true;
    }
  }

  private static KeyStatus parseStatus(KeyStatusType in) throws GeneralSecurityException {
    switch (in) {
      case ENABLED:
        return KeyStatus.ENABLED;
      case DISABLED:
        return KeyStatus.DISABLED;
      case DESTROYED:
        return KeyStatus.DESTROYED;
      default:
        throw new GeneralSecurityException("Unknown key status");
    }
  }

  private static KeyStatusType serializeStatus(KeyStatus in) {
    if (KeyStatus.ENABLED.equals(in)) {
      return KeyStatusType.ENABLED;
    }
    if (KeyStatus.DISABLED.equals(in)) {
      return KeyStatusType.DISABLED;
    }
    if (KeyStatus.DESTROYED.equals(in)) {
      return KeyStatusType.DESTROYED;
    }
    throw new IllegalStateException("Unknown key status");
  }

  /**
   * Returns an immutable list of key objects for this keyset.
   *
   * <p>If a status is unparseable or parsing of a key fails, there will be "null" in the
   * corresponding entry.
   */
  private static List<Entry> getEntriesFromKeyset(Keyset keyset) {
    List<Entry> result = new ArrayList<>(keyset.getKeyCount());
    for (Keyset.Key protoKey : keyset.getKeyList()) {
      int id = protoKey.getKeyId();
      try {
        Key key = toKey(protoKey);
        result.add(
            new KeysetHandle.Entry(
                key, parseStatus(protoKey.getStatus()), id, id == keyset.getPrimaryKeyId()));
      } catch (GeneralSecurityException e) {
        result.add(null);
      }
    }
    return Collections.unmodifiableList(result);
  }

  private KeysetHandle.Entry entryByIndex(int i) {
    if (entries.get(i) == null) {
      // This may happen if a keyset without status makes it here; or if a key has a parser
      // registered but parsing fails. We should reject such keysets earlier instead.
      throw new IllegalStateException(
          "Keyset-Entry at position " + i + " has wrong status or key parsing failed");
    }
    return entries.get(i);
  }

  /**
   * Creates a new entry with a fixed key.
   *
   * <p>If the Key has an IdRequirement, the default will be fixed to this ID. Otherwise, the user
   * has to specify the ID to be used and call one of {@code withFixedId(i)} or {@code
   * withRandomId()} on the returned entry.
   */
  public static KeysetHandle.Builder.Entry importKey(Key key) {
    KeysetHandle.Builder.Entry importedEntry = new KeysetHandle.Builder.Entry(key);
    @Nullable Integer requirement = key.getIdRequirementOrNull();
    if (requirement != null) {
      importedEntry.withFixedId(requirement);
    }
    return importedEntry;
  }

  /**
   * Creates a new entry with Status "ENABLED" and a new key created from the named parameters. No
   * ID is set.
   *
   * <p>{@code namedParameters} is the key template name that fully specifies the parameters, e.g.
   * "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM".
   */
  public static KeysetHandle.Builder.Entry generateEntryFromParametersName(String parametersName)
      throws GeneralSecurityException {
    Parameters parameters = MutableParametersRegistry.globalInstance().get(parametersName);
    return new KeysetHandle.Builder.Entry(parameters);
  }

  /**
   * Creates a new entry with Status "ENABLED" and a new key created from the parameters. No ID is
   * set.
   */
  public static KeysetHandle.Builder.Entry generateEntryFromParameters(Parameters parameters) {
    return new KeysetHandle.Builder.Entry(parameters);
  }

  private final Keyset keyset;
  /* Note: this should be List<@Nullable Entry>; but since we use the Nullable annotation from
   * javax.annotation it is not possible to do this.
   *
   * Contains all entries; but if either parsing the status or the key failed, contains null.
   */
  private final List<Entry> entries;
  private final MonitoringAnnotations annotations;

  private KeysetHandle(Keyset keyset, List<Entry> entries) {
    this.keyset = keyset;
    this.entries = entries;
    this.annotations = MonitoringAnnotations.EMPTY;
  }

  private KeysetHandle(
      Keyset keyset, List<Entry> entries, MonitoringAnnotations annotations) {
    this.keyset = keyset;
    this.entries = entries;
    this.annotations = annotations;
  }

  /**
   * @return a new {@link KeysetHandle} from a {@code keyset}.
   * @throws GeneralSecurityException if the keyset is null or empty.
   */
  static final KeysetHandle fromKeyset(Keyset keyset) throws GeneralSecurityException {
    assertEnoughKeyMaterial(keyset);
    List<Entry> entries = getEntriesFromKeyset(keyset);

    return new KeysetHandle(keyset, entries);
  }

  /**
   * @return a new {@link KeysetHandle} from a {@code keyset} and {@code annotations}.
   * @throws GeneralSecurityException if the keyset is null or empty.
   */
  static final KeysetHandle fromKeysetAndAnnotations(
      Keyset keyset, MonitoringAnnotations annotations) throws GeneralSecurityException {
    assertEnoughKeyMaterial(keyset);
    List<Entry> entries = getEntriesFromKeyset(keyset);
    return new KeysetHandle(keyset, entries, annotations);
  }

  /** Returns the actual keyset data. */
  Keyset getKeyset() {
    return keyset;
  }

  /** Creates a new builder. */
  public static Builder newBuilder() {
    return new Builder();
  }

  /** Creates a new builder, initially containing all entries from {@code handle}. */
  public static Builder newBuilder(KeysetHandle handle) {
    Builder builder = new Builder();
    for (int i = 0; i < handle.size(); ++i) {
      // Currently, this can be null (as old APIs do not check validity e.g. in {@link #fromKeyset})
      @Nullable KeysetHandle.Entry entry = handle.entries.get(i);
      if (entry == null) {
        builder.setErrorToThrow(
            new GeneralSecurityException(
                "Keyset-Entry in original keyset at position "
                    + i
                    + " has wrong status or key parsing failed"));
        break;
      }

      KeysetHandle.Builder.Entry builderEntry =
          importKey(entry.getKey()).withFixedId(entry.getId());
      builderEntry.setStatus(entry.getStatus());
      if (entry.isPrimary()) {
        builderEntry.makePrimary();
      }
      builder.addEntry(builderEntry);
    }
    return builder;
  }

  /**
   * Returns the unique entry where isPrimary() = true and getStatus() = ENABLED.
   *
   * <p>Note: currently this may throw IllegalStateException, since it is possible that keysets are
   * parsed without a primary. In the future, such keysets will be rejected when the keyset is
   * parsed.
   */
  public KeysetHandle.Entry getPrimary() {
    for (Entry entry : entries) {
      if (entry != null && entry.isPrimary()) {
        if (entry.getStatus() != KeyStatus.ENABLED) {
          throw new IllegalStateException("Keyset has primary which isn't enabled");
        }
        return entry;
      }
    }
    throw new IllegalStateException("Keyset has no valid primary");
  }

  /** Returns the size of this keyset. */
  public int size() {
    return entries.size();
  }

  /**
   * Returns the entry at index i. The order is preserved and depends on the order at which the
   * entries were inserted when the KeysetHandle was built.
   *
   * <p>Currently, this may throw "IllegalStateException" in case the status entry of the Key in the
   * keyset was wrongly set. In this case, we call this KeysetHandle invalid. In the future, Tink
   * will throw at parsing time in this case, and we will not have invalid KeysetHandles.
   *
   * <p>If you want to ensure that this does not throw an IllegalStateException, please first
   * re-parse the KeysetHandle: {@code KeysetHandle guaranteedValid =
   * KeysetHandle.newBuilder(maybeInvalidHandle).build();} (This would throw a {@code
   * GeneralSecurityException} if the {@code maybeInvalidHandle} handle is invalid).
   *
   * @throws IndexOutOfBoundsException if i < 0 or i >= size();
   */
  public KeysetHandle.Entry getAt(int i) {
    if (i < 0 || i >= size()) {
      throw new IndexOutOfBoundsException("Invalid index " + i + " for keyset of size " + size());
    }
    return entryByIndex(i);
  }

  /**
   * Returns the keyset data as a list of {@link KeyHandle}s.
   *
   * <p>Please do not use this function in new code. Instead, use {@link #getAt}.
   *
   * @deprecated Use "getAt" instead.
   */
  @Deprecated
  public List<KeyHandle> getKeys() {
    ArrayList<KeyHandle> result = new ArrayList<>();
    for (Keyset.Key key : keyset.getKeyList()) {
      KeyData keyData = key.getKeyData();
      result.add(
          new InternalKeyHandle(
              new ProtoKey(keyData, KeyTemplate.fromProto(key.getOutputPrefixType())),
              key.getStatus(),
              key.getKeyId()));
    }
    return Collections.unmodifiableList(result);
  }

  /**
   * Returns the {@link com.google.crypto.tink.proto.KeysetInfo} that doesn't contain actual key
   * material.
   */
  public KeysetInfo getKeysetInfo() {
    return Util.getKeysetInfo(keyset);
  }

  /**
   * Generates a new {@link KeysetHandle} that contains a single fresh key generated key with the
   * given {@code Parameters} object.
   *
   * @throws GeneralSecurityException if no generation method for the given {@code parameters} has
   *     been registered.
   */
  public static final KeysetHandle generateNew(Parameters parameters)
      throws GeneralSecurityException {
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId().makePrimary())
        .build();
  }

  /**
   * Generates a new {@link KeysetHandle} that contains a single fresh key generated according to
   * {@code keyTemplate}.
   *
   * <p>Please do not use this function. Instead, use {@link #generateNew(Parameters)}.
   *
   * <p>For existing usage, try to use refaster
   * https://github.com/tink-crypto/tink-java/tree/main/tools/refaster to replace usage
   * automatically. This will replaces calls {@code KeysetHandle.generateNew(XYZKeyTemplates.ABC);}
   * with {@code KeysetHandle.generateNew(PredefinedXYZParameters.ABC);} which is a NO-OP.
   *
   * <p>If this is not possible, please inline the function in your code.
   *
   * @throws GeneralSecurityException if the key template is invalid.
   * @deprecated Use the overload taking a Parameters object instead.
   */
  @Deprecated
  public static final KeysetHandle generateNew(
      com.google.crypto.tink.proto.KeyTemplate keyTemplate) throws GeneralSecurityException {
    return generateNew(TinkProtoParametersFormat.parse(keyTemplate.toByteArray()));
  }

  /**
   * Generates a new {@link KeysetHandle} that contains a single fresh key generated according to
   * {@code keyTemplate}.
   *
   * <p>Please do not use this function. Instead, inline it: replace calls with {@code
   * generateNew(t)} with {@code generateNew(t.toParameters())}.
   *
   * @throws GeneralSecurityException if the key template is invalid.
   */
  public static final KeysetHandle generateNew(KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    return generateNew(keyTemplate.toParameters());
  }

  /**
   * Returns a {@code KeysetHandle} that contains the single {@code KeyHandle} passed as input.
   *
   * @deprecated Use {@link KeysetHandle.Builder.addEntry} instead.
   */
  @Deprecated
  public static final KeysetHandle createFromKey(KeyHandle keyHandle, KeyAccess access)
      throws GeneralSecurityException {
    KeysetManager km = KeysetManager.withEmptyKeyset().add(keyHandle);
    km.setPrimary(km.getKeysetHandle().getKeysetInfo().getKeyInfo(0).getKeyId());
    return km.getKeysetHandle();
  }

  /**
   * Tries to create a {@link KeysetHandle} from an encrypted keyset obtained via {@code reader}.
   *
   * <p>Users that need to load cleartext keysets can use {@link CleartextKeysetHandle}.
   *
   * @return a new {@link KeysetHandle} from {@code encryptedKeysetProto} that was encrypted with
   *     {@code masterKey}
   * @throws GeneralSecurityException if cannot decrypt the keyset or it doesn't contain encrypted
   *     key material
   */
  public static final KeysetHandle read(KeysetReader reader, Aead masterKey)
      throws GeneralSecurityException, IOException {
    return readWithAssociatedData(reader, masterKey, new byte[0]);
  }

  /**
   * Tries to create a {@link KeysetHandle} from an encrypted keyset obtained via {@code reader},
   * using the provided associated data.
   *
   * <p>Users that need to load cleartext keysets can use {@link CleartextKeysetHandle}.
   *
   * @return a new {@link KeysetHandle} from {@code encryptedKeysetProto} that was encrypted with
   *     {@code masterKey}
   * @throws GeneralSecurityException if cannot decrypt the keyset or it doesn't contain encrypted
   *     key material
   */
  public static final KeysetHandle readWithAssociatedData(
      KeysetReader reader, Aead masterKey, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    EncryptedKeyset encryptedKeyset = reader.readEncrypted();
    assertEnoughEncryptedKeyMaterial(encryptedKeyset);
    return KeysetHandle.fromKeyset(decrypt(encryptedKeyset, masterKey, associatedData));
  }

  /**
   * Tries to create a {@link KeysetHandle} from a keyset, obtained via {@code reader}, which
   * contains no secret key material.
   *
   * <p>This can be used to load public keysets or envelope encryption keysets. Users that need to
   * load cleartext keysets can use {@link CleartextKeysetHandle}.
   *
   * @return a new {@link KeysetHandle} from {@code serialized} that is a serialized {@link Keyset}
   * @throws GeneralSecurityException if the keyset is invalid
   */
  @SuppressWarnings("UnusedException")
  public static final KeysetHandle readNoSecret(KeysetReader reader)
      throws GeneralSecurityException, IOException {
    byte[] serializedKeyset;
    try {
      serializedKeyset = reader.read().toByteArray();
    } catch (InvalidProtocolBufferException e) {
      // Do not propagate InvalidProtocolBufferException to guarantee no key material is leaked
      throw new GeneralSecurityException("invalid keyset");
    }
    return readNoSecret(serializedKeyset);
  }

  /**
   * Tries to create a {@link KeysetHandle} from a serialized keyset which contains no secret key
   * material.
   *
   * <p>This can be used to load public keysets or envelope encryption keysets. Users that need to
   * load cleartext keysets can use {@link CleartextKeysetHandle}.
   *
   * <p>Note: new code should call {@code TinkProtoKeysetFormat(serialized)} instead.
   *
   * @return a new {@link KeysetHandle} from {@code serialized} that is a serialized {@link Keyset}
   * @throws GeneralSecurityException if the keyset is invalid
   * @deprecated Call {TinkProtoKeysetFormat.parseKeysetWithoutSecret} instead.
   */
  @SuppressWarnings("UnusedException")
  @Deprecated
  public static final KeysetHandle readNoSecret(final byte[] serialized)
      throws GeneralSecurityException {
    try {
      Keyset keyset = Keyset.parseFrom(serialized, ExtensionRegistryLite.getEmptyRegistry());
      assertNoSecretKeyMaterial(keyset);
      return KeysetHandle.fromKeyset(keyset);
    } catch (InvalidProtocolBufferException e) {
      // Do not propagate InvalidProtocolBufferException to guarantee no key material is leaked
      throw new GeneralSecurityException("invalid keyset");
    }
  }

  /** Serializes, encrypts with {@code masterKey} and writes the keyset to {@code outputStream}. */
  public void write(KeysetWriter keysetWriter, Aead masterKey)
      throws GeneralSecurityException, IOException {
    writeWithAssociatedData(keysetWriter, masterKey, new byte[0]);
  }

  /**
   * Serializes, encrypts with {@code masterKey} and writes the keyset to {@code outputStream} using
   * the provided associated data.
   */
  public void writeWithAssociatedData(
      KeysetWriter keysetWriter, Aead masterKey, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    EncryptedKeyset encryptedKeyset = encrypt(keyset, masterKey, associatedData);
    keysetWriter.write(encryptedKeyset);
  }

  /**
   * Tries to write to {@code writer} this keyset which must not contain any secret key material.
   *
   * <p>This can be used to persist public keysets or envelope encryption keysets. Users that need
   * to persist cleartext keysets can use {@link CleartextKeysetHandle}.
   *
   * @throws GeneralSecurityException if the keyset contains any secret key material
   */
  public void writeNoSecret(KeysetWriter writer) throws GeneralSecurityException, IOException {
    assertNoSecretKeyMaterial(keyset);
    writer.write(keyset);
  }

  /** Encrypts the keyset with the {@link Aead} master key. */
  @SuppressWarnings("UnusedException")
  private static EncryptedKeyset encrypt(Keyset keyset, Aead masterKey, byte[] associatedData)
      throws GeneralSecurityException {
    byte[] encryptedKeyset = masterKey.encrypt(keyset.toByteArray(), associatedData);
    // Check if we can decrypt, to detect errors
    try {
      final Keyset keyset2 =
          Keyset.parseFrom(
              masterKey.decrypt(encryptedKeyset, associatedData),
              ExtensionRegistryLite.getEmptyRegistry());
      if (!keyset2.equals(keyset)) {
        throw new GeneralSecurityException("cannot encrypt keyset");
      }
    } catch (InvalidProtocolBufferException e) {
      // Do not propagate InvalidProtocolBufferException to guarantee no key material is leaked
      throw new GeneralSecurityException("invalid keyset, corrupted key material");
    }
    return EncryptedKeyset.newBuilder()
        .setEncryptedKeyset(ByteString.copyFrom(encryptedKeyset))
        .setKeysetInfo(Util.getKeysetInfo(keyset))
        .build();
  }

  /** Decrypts the encrypted keyset with the {@link Aead} master key. */
  @SuppressWarnings("UnusedException")
  private static Keyset decrypt(
      EncryptedKeyset encryptedKeyset, Aead masterKey, byte[] associatedData)
      throws GeneralSecurityException {
    try {
      Keyset keyset =
          Keyset.parseFrom(
              masterKey.decrypt(encryptedKeyset.getEncryptedKeyset().toByteArray(), associatedData),
              ExtensionRegistryLite.getEmptyRegistry());
      // check emptiness here too, in case the encrypted keys unwrapped to nothing?
      assertEnoughKeyMaterial(keyset);
      return keyset;
    } catch (InvalidProtocolBufferException e) {
      // Do not propagate InvalidProtocolBufferException to guarantee no key material is leaked
      throw new GeneralSecurityException("invalid keyset, corrupted key material");
    }
  }

  /**
   * If the managed keyset contains private keys, returns a {@link KeysetHandle} of the public keys.
   *
   * @throws GeneralSecurityException if the managed keyset is null or if it contains any
   *     non-private keys.
   */
  public KeysetHandle getPublicKeysetHandle() throws GeneralSecurityException {
    if (keyset == null) {
      throw new GeneralSecurityException("cleartext keyset is not available");
    }

    Keyset.Builder publicKeysetBuilder = Keyset.newBuilder();
    List<KeysetHandle.Entry> publicEntries = new ArrayList<>(entries.size());

    int i = 0;
    for (KeysetHandle.Entry entry : entries) {
      KeysetHandle.Entry publicEntry;
      Keyset.Key publicProtoKey;

      if (entry != null && entry.getKey() instanceof PrivateKey) {
        Key publicKey = ((PrivateKey) entry.getKey()).getPublicKey();
        publicEntry =
            new KeysetHandle.Entry(publicKey, entry.getStatus(), entry.getId(), entry.isPrimary());
        publicProtoKey = createKeysetKey(publicKey, entry.getStatus(), entry.getId());
      } else {
        Keyset.Key protoKey = keyset.getKey(i);
        KeyData keyData = getPublicKeyDataFromRegistry(protoKey.getKeyData());
        publicProtoKey = protoKey.toBuilder().setKeyData(keyData).build();
        try {
          Key publicKey = toKey(publicProtoKey);
          int id = publicProtoKey.getKeyId();
          publicEntry =
              new KeysetHandle.Entry(
                  publicKey,
                  parseStatus(publicProtoKey.getStatus()),
                  id,
                  id == keyset.getPrimaryKeyId());
        } catch (GeneralSecurityException e) {
          publicEntry = null;
        }
      }

      publicKeysetBuilder.addKey(publicProtoKey);
      publicEntries.add(publicEntry);
      i++;
    }
    publicKeysetBuilder.setPrimaryKeyId(keyset.getPrimaryKeyId());
    return new KeysetHandle(publicKeysetBuilder.build(), publicEntries, annotations);
  }

  private static KeyData getPublicKeyDataFromRegistry(KeyData privateKeyData)
      throws GeneralSecurityException {
    if (privateKeyData.getKeyMaterialType() != KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE) {
      throw new GeneralSecurityException("The keyset contains a non-private key");
    }
    KeyData publicKeyData =
        Registry.getPublicKeyData(privateKeyData.getTypeUrl(), privateKeyData.getValue());
    return publicKeyData;
  }

  /**
   * Extracts and returns the string representation of the {@link
   * com.google.crypto.tink.proto.KeysetInfo} of the managed keyset.
   */
  @SuppressWarnings("LiteProtoToString") // main purpose of toString is for debugging
  @Override
  public String toString() {
    return getKeysetInfo().toString();
  }

  /**
   * Validates that {@code keyset} doesn't contain any secret key material.
   *
   * @throws GeneralSecurityException if {@code keyset} contains secret key material.
   */
  private static void assertNoSecretKeyMaterial(Keyset keyset) throws GeneralSecurityException {
    for (Keyset.Key key : keyset.getKeyList()) {
      if (key.getKeyData().getKeyMaterialType() == KeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL
          || key.getKeyData().getKeyMaterialType() == KeyData.KeyMaterialType.SYMMETRIC
          || key.getKeyData().getKeyMaterialType() == KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE) {
        throw new GeneralSecurityException(
            String.format(
                "keyset contains key material of type %s for type url %s",
                key.getKeyData().getKeyMaterialType().name(), key.getKeyData().getTypeUrl()));
      }
    }
  }

  /**
   * Validates that a keyset handle contains enough key material to build a keyset on.
   *
   * @throws GeneralSecurityException if the validation fails
   */
  private static void assertEnoughKeyMaterial(Keyset keyset) throws GeneralSecurityException {
    if (keyset == null || keyset.getKeyCount() <= 0) {
      throw new GeneralSecurityException("empty keyset");
    }
  }

  /**
   * Validates that an encrypted keyset contains enough key material to build a keyset on.
   *
   * @throws GeneralSecurityException if the validation fails
   */
  private static void assertEnoughEncryptedKeyMaterial(EncryptedKeyset keyset)
      throws GeneralSecurityException {
    if (keyset == null || keyset.getEncryptedKeyset().size() == 0) {
      throw new GeneralSecurityException("empty keyset");
    }
  }

  /** Allows us to have a name {@code B} for the base primitive. */
  private <B, P> P getPrimitiveWithKnownInputPrimitive(
      InternalConfiguration config, Class<P> classObject, Class<B> inputPrimitiveClassObject)
      throws GeneralSecurityException {
    Util.validateKeyset(keyset);
    PrimitiveSet.Builder<B> builder = PrimitiveSet.newBuilder(inputPrimitiveClassObject);
    builder.setAnnotations(annotations);
    for (int i = 0; i < size(); ++i) {
      Keyset.Key protoKey = keyset.getKey(i);
      if (protoKey.getStatus().equals(KeyStatusType.ENABLED)) {
        KeysetHandle.Entry entry = entries.get(i);
        // entry may be null (if the status is invalid in the proto, or parsing failed).
        if (entry == null) {
          throw new GeneralSecurityException(
              "Key parsing of key with index "
                  + i
                  + " and type_url "
                  + protoKey.getKeyData().getTypeUrl()
                  + " failed, unable to get primitive");
        }
        Key key = entry.getKey();
        // TODO(tholenst) Pass the exception from getFullPrimitiveOrNull.
        @Nullable B fullPrimitive = getFullPrimitiveOrNull(config, key, inputPrimitiveClassObject);
        if (fullPrimitive == null) {
          throw new GeneralSecurityException(
              "Unable to get primitive "
                  + inputPrimitiveClassObject
                  + " for key of type "
                  + protoKey.getKeyData().getTypeUrl()
                  + ", see https://developers.google.com/tink/registration_errors");
        }
        if (protoKey.getKeyId() == keyset.getPrimaryKeyId()) {
          builder.addPrimaryFullPrimitive(fullPrimitive, key, protoKey);
        } else {
          builder.addFullPrimitive(fullPrimitive, key, protoKey);
        }
      }
    }
    return config.wrap(builder.build(), classObject);
  }

  /**
   * Returns a primitive from this keyset using the provided {@link Configuration} to create
   * resources used in creating the primitive.
   */
  public <P> P getPrimitive(Configuration configuration, Class<P> targetClassObject)
      throws GeneralSecurityException {
    if (!(configuration instanceof InternalConfiguration)) {
      throw new GeneralSecurityException(
          "Currently only subclasses of InternalConfiguration are accepted");
    }
    InternalConfiguration internalConfig = (InternalConfiguration) configuration;
    Class<?> inputPrimitiveClassObject = internalConfig.getInputPrimitiveClass(targetClassObject);
    if (inputPrimitiveClassObject == null) {
      throw new GeneralSecurityException("No wrapper found for " + targetClassObject.getName());
    }
    return getPrimitiveWithKnownInputPrimitive(
        internalConfig, targetClassObject, inputPrimitiveClassObject);
  }

  /**
   * Returns a primitive from this keyset, using the global registry to create resources creating
   * the primitive.
   */
  public <P> P getPrimitive(Class<P> targetClassObject) throws GeneralSecurityException {
    return getPrimitive(RegistryConfiguration.get(), targetClassObject);
  }

  /**
   * Searches the keyset to find the primary key of this {@code KeysetHandle}, and returns the key
   * wrapped in a {@code KeyHandle}.
   *
   * <p>Please do not use this function in new code. Instead, use {@link #getPrimary}.
   *
   * @deprecated Use {@link #getPrimary} instead.
   */
  @Deprecated
  public KeyHandle primaryKey() throws GeneralSecurityException {
    int primaryKeyId = keyset.getPrimaryKeyId();
    for (Keyset.Key key : keyset.getKeyList()) {
      if (key.getKeyId() == primaryKeyId) {
        return new InternalKeyHandle(
            new ProtoKey(key.getKeyData(), KeyTemplate.fromProto(key.getOutputPrefixType())),
            key.getStatus(),
            key.getKeyId());
      }
    }
    throw new GeneralSecurityException("No primary key found in keyset.");
  }

  @Nullable
  private <B> B getFullPrimitiveOrNull(
      InternalConfiguration config, Key key, Class<B> inputPrimitiveClassObject)
      throws GeneralSecurityException {
    try {
      return config.getPrimitive(key, inputPrimitiveClassObject);
    } catch (GeneralSecurityException e) {
      // Ignoring because the key may not yet have a corresponding class.
      // TODO(lizatretyakova): stop ignoring when all key classes are migrated from protos.
      return null;
    }
  }

  /**
   * Returns true if this keyset is equal to {@code other}, ignoring monitoring annotations.
   *
   * <p>Note: this may return false even if the keysets represent the same set of functions. For
   * example, this can happen if the keys store zero-byte padding of a {@link java.math.BigInteger},
   * which are irrelevant to the function computed. Currently, keysets can also be invalid in which
   * case this will return false.
   */
  public boolean equalsKeyset(KeysetHandle other) {
    if (size() != other.size()) {
      return false;
    }
    boolean primaryFound = false;
    for (int i = 0; i < size(); ++i) {
      Entry thisEntry = entries.get(i);
      Entry otherEntry = other.entries.get(i);
      if (thisEntry == null) {
        // Can only happen for invalid keyset
        return false;
      }
      if (otherEntry == null) {
        // Can only happen for invalid keyset
        return false;
      }
      if (!thisEntry.equalsEntry(otherEntry)) {
        return false;
      }
      primaryFound |= thisEntry.isPrimary;
    }
    if (!primaryFound) {
      return false;
    }
    return true;
  }

  private static ProtoKeySerialization toProtoKeySerialization(Keyset.Key protoKey) {
    int id = protoKey.getKeyId();
    @Nullable
    Integer idRequirement = protoKey.getOutputPrefixType() == OutputPrefixType.RAW ? null : id;
    try {
      return ProtoKeySerialization.create(
          protoKey.getKeyData().getTypeUrl(),
          protoKey.getKeyData().getValue(),
          protoKey.getKeyData().getKeyMaterialType(),
          protoKey.getOutputPrefixType(),
          idRequirement);
    } catch (GeneralSecurityException e) {
      // Cannot happen -- this only happens if the idRequirement doesn't match OutputPrefixType
      throw new TinkBugException("Creating a protokey serialization failed", e);
    }
  }

  private static Key toKey(Keyset.Key protoKey) throws GeneralSecurityException {
    ProtoKeySerialization protoKeySerialization = toProtoKeySerialization(protoKey);
    return MutableSerializationRegistry.globalInstance()
        .parseKeyWithLegacyFallback(protoKeySerialization, InsecureSecretKeyAccess.get());
  }

  private static Keyset.Key toKeysetKey(
      int id, KeyStatusType status, ProtoKeySerialization protoKeySerialization) {
    return Keyset.Key.newBuilder()
        .setKeyData(
            KeyData.newBuilder()
                .setTypeUrl(protoKeySerialization.getTypeUrl())
                .setValue(protoKeySerialization.getValue())
                .setKeyMaterialType(protoKeySerialization.getKeyMaterialType()))
        .setStatus(status)
        .setKeyId(id)
        .setOutputPrefixType(protoKeySerialization.getOutputPrefixType())
        .build();
  }

  private static Keyset.Key createKeysetKey(Key key, KeyStatus keyStatus, int id)
      throws GeneralSecurityException {
    ProtoKeySerialization serializedKey =
        MutableSerializationRegistry.globalInstance()
            .serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    @Nullable Integer idRequirement = serializedKey.getIdRequirementOrNull();
    if (idRequirement != null && idRequirement != id) {
      throw new GeneralSecurityException("Wrong ID set for key with ID requirement");
    }
    return toKeysetKey(id, serializeStatus(keyStatus), serializedKey);
  }
}
