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

package com.google.crypto.tink.internal;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyFormat;
import com.google.crypto.tink.SecretKeyAccess;
import java.security.GeneralSecurityException;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A Mutable version of the {@link SerializationRegistry}.
 *
 * <p>This class probably shouldn't exist; it would be better if we had only the
 * SerializationRegistry. However, at the moment, we need this, since a call to e.g.
 *
 * <pre> AesCmacKeyManager.register() </pre>
 *
 * should register such an object into a global, mutable registry.
 */
public final class MutableSerializationRegistry {
  private static final MutableSerializationRegistry GLOBAL_INSTANCE =
      new MutableSerializationRegistry();

  public static MutableSerializationRegistry globalInstance() {
    return GLOBAL_INSTANCE;
  }

  private final AtomicReference<SerializationRegistry> registry =
      new AtomicReference<>(new SerializationRegistry.Builder().build());

  public MutableSerializationRegistry() {}

  /**
   * Registers a key serializer for later use in {@link #serializeKey}.
   *
   * <p>This registers a key serializer which can later be used to serialize a key by calling {@link
   * #serializeKey}. If a serializer for the pair {@code (KeyT, SerializationT)} has already been
   * registered, this checks if they are the same. If they are, the call is ignored, otherwise an
   * exception is thrown, and the object is unchanged.
   */
  public synchronized <KeyT extends Key, SerializationT extends Serialization>
      void registerKeySerializer(KeySerializer<KeyT, SerializationT> serializer)
          throws GeneralSecurityException {
    SerializationRegistry newRegistry =
        new SerializationRegistry.Builder(registry.get()).registerKeySerializer(serializer).build();
    registry.set(newRegistry);
  }

  /**
   * Registers a key parser for later use in {@link #parseKey}.
   *
   * <p>This registers a key serializer which can later be used to serialize a key by calling {@link
   * #parseKey}. If a parser for the pair {@code (SerializationT, parser.getObjectIdentifier())} has
   * already been registered, this checks if they are the same. If they are, the call is ignored,
   * otherwise an exception is thrown, and the object is unchanged.
   */
  public synchronized <SerializationT extends Serialization> void registerKeyParser(
      KeyParser<SerializationT> parser) throws GeneralSecurityException {
    SerializationRegistry newRegistry =
        new SerializationRegistry.Builder(registry.get()).registerKeyParser(parser).build();
    registry.set(newRegistry);
  }

  /**
   * Registers a key serializer for later use in {@link #serializeKey}.
   *
   * <p>This registers a key serializer which can later be used to serialize a key by calling {@link
   * #serializeKey}. If a serializer for the pair {@code (KeyT, SerializationT)} has already been
   * registered, this checks if they are the same. If they are, the call is ignored, otherwise an
   * exception is thrown, and the object is unchanged.
   */
  public synchronized <KeyFormatT extends KeyFormat, SerializationT extends Serialization>
      void registerKeyFormatSerializer(KeyFormatSerializer<KeyFormatT, SerializationT> serializer)
          throws GeneralSecurityException {
    SerializationRegistry newRegistry =
        new SerializationRegistry.Builder(registry.get())
            .registerKeyFormatSerializer(serializer)
            .build();
    registry.set(newRegistry);
  }

  /**
   * Registers a key parser for later use in {@link #parseKey}.
   *
   * <p>This registers a key serializer which can later be used to serialize a key by calling {@link
   * #parseKey}. If a parser for the pair {@code (SerializationT, parser.getObjectIdentifier())} has
   * already been registered, this checks if they are the same. If they are, the call is ignored,
   * otherwise an exception is thrown, and the object is unchanged.
   */
  public synchronized <SerializationT extends Serialization> void registerKeyFormatParser(
      KeyFormatParser<SerializationT> parser) throws GeneralSecurityException {
    SerializationRegistry newRegistry =
        new SerializationRegistry.Builder(registry.get()).registerKeyFormatParser(parser).build();
    registry.set(newRegistry);
  }

  /**
   * Parses the given serialization into a Key.
   *
   * <p>This will look up a previously registered parser for the passed in {@code SerializationT}
   * class, and the used object identifier (as indicated by {@code
   * serializedKey.getObjectIdentifier()}), and then parse the object with this parsers.
   */
  public <SerializationT extends Serialization> Key parseKey(
      SerializationT serializedKey, Optional<SecretKeyAccess> access)
      throws GeneralSecurityException {
    return registry.get().parseKey(serializedKey, access);
  }

  /**
   * Serializes a given Key into a "SerializationT" object.
   *
   * <p>This will look up a previously registered serializer for the requested {@code
   * SerializationT} class and the passed in key type, and then call serializeKey on the result.
   */
  public <KeyT extends Key, SerializationT extends Serialization> SerializationT serializeKey(
      KeyT key, Class<SerializationT> serializationClass, Optional<SecretKeyAccess> access)
      throws GeneralSecurityException {
    return registry.get().serializeKey(key, serializationClass, access);
  }

  /**
   * Parses the given serialization into a KeyFormat.
   *
   * <p>This will look up a previously registered parser for the passed in {@code SerializationT}
   * class, and the used object identifier (as indicated by {@code
   * serializedKey.getObjectIdentifier()}), and then parse the object with this parsers.
   */
  public <SerializationT extends Serialization> KeyFormat parseKeyFormat(
      SerializationT serializedKeyFormat) throws GeneralSecurityException {
    return registry.get().parseKeyFormat(serializedKeyFormat);
  }

  /**
   * Serializes a given KeyFormat into a "SerializationT" object.
   *
   * <p>This will look up a previously registered serializer for the requested {@code
   * SerializationT} class and the passed in key type, and then call serializeKey on the result.
   */
  public <KeyFormatT extends KeyFormat, SerializationT extends Serialization>
      SerializationT serializeKeyFormat(
          KeyFormatT keyFormat, Class<SerializationT> serializationClass)
          throws GeneralSecurityException {
    return registry.get().serializeKeyFormat(keyFormat, serializationClass);
  }
}
