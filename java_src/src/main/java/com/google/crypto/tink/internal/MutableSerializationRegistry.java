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

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import java.security.GeneralSecurityException;
import java.util.concurrent.atomic.AtomicReference;
import javax.annotation.Nullable;

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
  private static MutableSerializationRegistry createGlobalInstance()
      throws GeneralSecurityException {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    registry.registerKeySerializer(
        KeySerializer.create(
            LegacyProtoKey::getSerialization, LegacyProtoKey.class, ProtoKeySerialization.class));
    return registry;
  }

  private static final MutableSerializationRegistry GLOBAL_INSTANCE =
      exceptionIsBug(MutableSerializationRegistry::createGlobalInstance);

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
  public synchronized <ParametersT extends Parameters, SerializationT extends Serialization>
      void registerParametersSerializer(
          ParametersSerializer<ParametersT, SerializationT> serializer)
          throws GeneralSecurityException {
    SerializationRegistry newRegistry =
        new SerializationRegistry.Builder(registry.get())
            .registerParametersSerializer(serializer)
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
  public synchronized <SerializationT extends Serialization> void registerParametersParser(
      ParametersParser<SerializationT> parser) throws GeneralSecurityException {
    SerializationRegistry newRegistry =
        new SerializationRegistry.Builder(registry.get()).registerParametersParser(parser).build();
    registry.set(newRegistry);
  }

  /** Returns true if a parser for this {@code serializedKey} has been registered. */
  public <SerializationT extends Serialization> boolean hasParserForKey(
      SerializationT serializedKey) {
    return registry.get().hasParserForKey(serializedKey);
  }

  /**
   * Parses the given serialization into a Key.
   *
   * <p>This will look up a previously registered parser for the passed in {@code SerializationT}
   * class, and the used object identifier (as indicated by {@code
   * serializedKey.getObjectIdentifier()}), and then parse the object with this parsers.
   */
  public <SerializationT extends Serialization> Key parseKey(
      SerializationT serializedKey, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return registry.get().parseKey(serializedKey, access);
  }

  /**
   * Returns a Key object from a protoKeySerialization, even if no parser has been registered.
   *
   * <p>Falling back is useful because we want users to be able to call {@code #getAt} even for key
   * types for which we did not yet register a parser; in this case we simply fall back to return a
   * LegacyProtoKey.
   *
   * @throws GeneralSecurityException if a parser is registered but parsing fails or required
   *     SecretKeyAccess is missing
   */
  public Key parseKeyWithLegacyFallback(
      ProtoKeySerialization protoKeySerialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!hasParserForKey(protoKeySerialization)) {
      return new LegacyProtoKey(protoKeySerialization, access);
    }
    return parseKey(protoKeySerialization, access);
  }


  /** Returns true if a parser for this {@code serializedKey} has been registered. */
  public <KeyT extends Key, SerializationT extends Serialization> boolean hasSerializerForKey(
      KeyT key, Class<SerializationT> serializationClass) {
    return registry.get().hasSerializerForKey(key, serializationClass);
  }

  /**
   * Serializes a given Key into a "SerializationT" object.
   *
   * <p>This will look up a previously registered serializer for the requested {@code
   * SerializationT} class and the passed in key type, and then call serializeKey on the result.
   */
  public <KeyT extends Key, SerializationT extends Serialization> SerializationT serializeKey(
      KeyT key, Class<SerializationT> serializationClass, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return registry.get().serializeKey(key, serializationClass, access);
  }

  /** Returns true if a parser for this {@code serializedKey} has been registered. */
  public <SerializationT extends Serialization> boolean hasParserForParameters(
      SerializationT serializedParameters) {
    return registry.get().hasParserForParameters(serializedParameters);
  }

  /**
   * Parses the given serialization into a Parameters object.
   *
   * <p>This will look up a previously registered parser for the passed in {@code SerializationT}
   * class, and the used object identifier (as indicated by {@code
   * serializedKey.getObjectIdentifier()}), and then parse the object with this parsers.
   */
  public <SerializationT extends Serialization> Parameters parseParameters(
      SerializationT serializedParameters) throws GeneralSecurityException {
    return registry.get().parseParameters(serializedParameters);
  }

  /**
   * Returns a Parameters object from a protoKeySerialization, even if no parser has been
   * registered.
   *
   * <p>Falling back is useful because we need to have a parameters object even if no parser is
   * registered (e.g. for when we create a Key from a key template/parameters name object).
   */
  public Parameters parseParametersWithLegacyFallback(
      ProtoParametersSerialization protoParametersSerialization) throws GeneralSecurityException {
    if (!hasParserForParameters(protoParametersSerialization)) {
      return new LegacyProtoParameters(protoParametersSerialization);
    } else {
      return parseParameters(protoParametersSerialization);
    }
  }

  /** Returns true if a parser for this {@code serializedKey} has been registered. */
  public <ParametersT extends Parameters, SerializationT extends Serialization>
      boolean hasSerializerForParameters(
          ParametersT parameters, Class<SerializationT> serializationClass) {
    return registry.get().hasSerializerForParameters(parameters, serializationClass);
  }

  /**
   * Serializes a given Parameters object into a "SerializationT" object.
   *
   * <p>This will look up a previously registered serializer for the requested {@code
   * SerializationT} class and the passed in key type, and then call serializeKey on the result.
   */
  public <ParametersT extends Parameters, SerializationT extends Serialization>
      SerializationT serializeParameters(
          ParametersT parameters, Class<SerializationT> serializationClass)
          throws GeneralSecurityException {
    return registry.get().serializeParameters(parameters, serializationClass);
  }
}
