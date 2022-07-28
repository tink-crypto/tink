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
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Allows registering {@code KeySerializer}, {@code KeyParser}, {@code ParametersSerializer}, and
 * {@ParametersParser} objects, and parsing/serializing keys and key formats with such objects.
 */
public final class SerializationRegistry {
  private final Map<SerializerIndex, KeySerializer<?, ?>> keySerializerMap;
  private final Map<ParserIndex, KeyParser<?>> keyParserMap;
  private final Map<SerializerIndex, ParametersSerializer<?, ?>> parametersSerializerMap;
  private final Map<ParserIndex, ParametersParser<?>> parametersParserMap;

  /** Allows building SerializationRegistry objects. */
  public static final class Builder {
    private final Map<SerializerIndex, KeySerializer<?, ?>> keySerializerMap;
    private final Map<ParserIndex, KeyParser<?>> keyParserMap;
    private final Map<SerializerIndex, ParametersSerializer<?, ?>> parametersSerializerMap;
    private final Map<ParserIndex, ParametersParser<?>> parametersParserMap;

    public Builder() {
      keySerializerMap = new HashMap<>();
      keyParserMap = new HashMap<>();
      parametersSerializerMap = new HashMap<>();
      parametersParserMap = new HashMap<>();
    }

    public Builder(SerializationRegistry registry) {
      keySerializerMap = new HashMap<>(registry.keySerializerMap);
      keyParserMap = new HashMap<>(registry.keyParserMap);
      parametersSerializerMap = new HashMap<>(registry.parametersSerializerMap);
      parametersParserMap = new HashMap<>(registry.parametersParserMap);
    }

    /**
     * Registers a key serializer for later use in {@link #serializeKey}.
     *
     * <p>This registers a key serializer which can later be used to serialize a key by calling
     * {@link #serializeKey}. If a serializer for the pair {@code (KeyT, SerializationT)} has
     * already been registered, this checks if they are the same. If they are, the call is ignored,
     * otherwise an exception is thrown.
     */
    public <KeyT extends Key, SerializationT extends Serialization> Builder registerKeySerializer(
        KeySerializer<KeyT, SerializationT> serializer) throws GeneralSecurityException {
      SerializerIndex index =
          new SerializerIndex(serializer.getKeyClass(), serializer.getSerializationClass());
      if (keySerializerMap.containsKey(index)) {
        KeySerializer<?, ?> existingSerializer = keySerializerMap.get(index);
        if (!existingSerializer.equals(serializer) || !serializer.equals(existingSerializer)) {
          throw new GeneralSecurityException(
              "Attempt to register non-equal serializer for already existing object of type: "
                  + index);
        }
      } else {
        keySerializerMap.put(index, serializer);
      }
      return this;
    }

    /**
     * Registers a key parser for later use in {@link #parseKey}.
     *
     * <p>This registers a key serializer which can later be used to serialize a key by calling
     * {@link #parseKey}. If a parser for the pair {@code (SerializationT,
     * parser.getObjectIdentifier())} has already been registered, this checks if they are the same.
     * If they are, the call is ignored, otherwise an exception is thrown.
     */
    public <SerializationT extends Serialization> Builder registerKeyParser(
        KeyParser<SerializationT> parser) throws GeneralSecurityException {
      ParserIndex index =
          new ParserIndex(parser.getSerializationClass(), parser.getObjectIdentifier());
      if (keyParserMap.containsKey(index)) {
        KeyParser<?> existingParser = keyParserMap.get(index);
        if (!existingParser.equals(parser) || !parser.equals(existingParser)) {
          throw new GeneralSecurityException(
              "Attempt to register non-equal parser for already existing object of type: " + index);
        }
      } else {
        keyParserMap.put(index, parser);
      }
      return this;
    }

    /**
     * Registers a key serializer for later use in {@link #serializeKey}.
     *
     * <p>This registers a key serializer which can later be used to serialize a key by calling
     * {@link #serializeKey}. If a serializer for the pair {@code (KeyT, SerializationT)} has
     * already been registered, this checks if they are the same. If they are, the call is ignored,
     * otherwise an exception is thrown.
     */
    public <ParametersT extends Parameters, SerializationT extends Serialization>
        Builder registerParametersSerializer(
            ParametersSerializer<ParametersT, SerializationT> serializer)
            throws GeneralSecurityException {
      SerializerIndex index =
          new SerializerIndex(serializer.getParametersClass(), serializer.getSerializationClass());
      if (parametersSerializerMap.containsKey(index)) {
        ParametersSerializer<?, ?> existingSerializer = parametersSerializerMap.get(index);
        if (!existingSerializer.equals(serializer) || !serializer.equals(existingSerializer)) {
          throw new GeneralSecurityException(
              "Attempt to register non-equal serializer for already existing object of type: "
                  + index);
        }
      } else {
        parametersSerializerMap.put(index, serializer);
      }
      return this;
    }

    /**
     * Registers a key parser for later use in {@link #parseKey}.
     *
     * <p>This registers a key serializer which can later be used to serialize a key by calling
     * {@link #parseKey}. If a parser for the pair {@code (SerializationT,
     * parser.getObjectIdentifier())} has already been registered, this checks if they are the same.
     * If they are, the call is ignored, otherwise an exception is thrown.
     */
    public <SerializationT extends Serialization> Builder registerParametersParser(
        ParametersParser<SerializationT> parser) throws GeneralSecurityException {
      ParserIndex index =
          new ParserIndex(parser.getSerializationClass(), parser.getObjectIdentifier());
      if (parametersParserMap.containsKey(index)) {
        ParametersParser<?> existingParser = parametersParserMap.get(index);
        if (!existingParser.equals(parser) || !parser.equals(existingParser)) {
          throw new GeneralSecurityException(
              "Attempt to register non-equal parser for already existing object of type: " + index);
        }
      } else {
        parametersParserMap.put(index, parser);
      }
      return this;
    }

    SerializationRegistry build() {
      return new SerializationRegistry(this);
    }
  }

  private SerializationRegistry(Builder builder) {
    keySerializerMap = new HashMap<>(builder.keySerializerMap);
    keyParserMap = new HashMap<>(builder.keyParserMap);
    parametersSerializerMap = new HashMap<>(builder.parametersSerializerMap);
    parametersParserMap = new HashMap<>(builder.parametersParserMap);
  }

  private static class SerializerIndex {
    private final Class<?> keyClass;
    private final Class<? extends Serialization> keySerializationClass;

    private SerializerIndex(
        Class<?> keyClass, Class<? extends Serialization> keySerializationClass) {
      this.keyClass = keyClass;
      this.keySerializationClass = keySerializationClass;
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof SerializerIndex)) {
        return false;
      }
      SerializerIndex other = (SerializerIndex) o;
      return other.keyClass.equals(keyClass)
          && other.keySerializationClass.equals(keySerializationClass);
    }

    @Override
    public int hashCode() {
      return Objects.hash(keyClass, keySerializationClass);
    }

    @Override
    public String toString() {
      return keyClass.getSimpleName()
          + " with serialization type: "
          + keySerializationClass.getSimpleName();
    }
  }

  private static class ParserIndex {
    private final Class<? extends Serialization> keySerializationClass;
    private final Bytes serializationIdentifier;

    private ParserIndex(
        Class<? extends Serialization> keySerializationClass, Bytes serializationIdentifier) {
      this.keySerializationClass = keySerializationClass;
      this.serializationIdentifier = serializationIdentifier;
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof ParserIndex)) {
        return false;
      }
      ParserIndex other = (ParserIndex) o;
      return other.keySerializationClass.equals(keySerializationClass)
          && other.serializationIdentifier.equals(serializationIdentifier);
    }

    @Override
    public int hashCode() {
      return Objects.hash(keySerializationClass, serializationIdentifier);
    }

    @Override
    public String toString() {
      return keySerializationClass.getSimpleName()
          + ", object identifier: "
          + serializationIdentifier;
    }
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
    ParserIndex index =
        new ParserIndex(serializedKey.getClass(), serializedKey.getObjectIdentifier());

    if (!keyParserMap.containsKey(index)) {
      throw new GeneralSecurityException(
          "No Key Parser for requested key type " + index + " available");
    }
    @SuppressWarnings("unchecked") // We know we only insert like this.
    KeyParser<SerializationT> parser = (KeyParser<SerializationT>) keyParserMap.get(index);
    return parser.parseKey(serializedKey, access);
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
    SerializerIndex index = new SerializerIndex(key.getClass(), serializationClass);
    if (!keySerializerMap.containsKey(index)) {
      throw new GeneralSecurityException("No Key serializer for " + index + " available");
    }
    @SuppressWarnings("unchecked") // We know we only insert like this.
    KeySerializer<KeyT, SerializationT> serializer =
        (KeySerializer<KeyT, SerializationT>) keySerializerMap.get(index);
    return serializer.serializeKey(key, access);
  }

  /**
   * Parses the given serialization into a Parameters.
   *
   * <p>This will look up a previously registered parser for the passed in {@code SerializationT}
   * class, and the used object identifier (as indicated by {@code
   * serializedKey.getObjectIdentifier()}), and then parse the object with this parsers.
   */
  public <SerializationT extends Serialization> Parameters parseParameters(
      SerializationT serializedParameters) throws GeneralSecurityException {
    ParserIndex index =
        new ParserIndex(
            serializedParameters.getClass(), serializedParameters.getObjectIdentifier());

    if (!parametersParserMap.containsKey(index)) {
      throw new GeneralSecurityException(
          "No Parameters Parser for requested key type " + index + " available");
    }
    @SuppressWarnings("unchecked") // We know we only insert like this.
    ParametersParser<SerializationT> parser =
        (ParametersParser<SerializationT>) parametersParserMap.get(index);
    return parser.parseParameters(serializedParameters);
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
    SerializerIndex index = new SerializerIndex(parameters.getClass(), serializationClass);
    if (!parametersSerializerMap.containsKey(index)) {
      throw new GeneralSecurityException("No Key Format serializer for " + index + " available");
    }
    @SuppressWarnings("unchecked") // We know we only insert like this.
    ParametersSerializer<ParametersT, SerializationT> serializer =
        (ParametersSerializer<ParametersT, SerializationT>) parametersSerializerMap.get(index);
    return serializer.serializeParameters(parameters);
  }
}
