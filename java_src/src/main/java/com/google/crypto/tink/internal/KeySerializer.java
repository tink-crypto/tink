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
import com.google.crypto.tink.SecretKeyAccess;
import java.security.GeneralSecurityException;
import java.util.Optional;

/**
 * Serializes {@code Key} objects into {@code Serialization} objects of a certain kind.
 *
 * <p>This class should eventually be in Tinks public API -- however, it might still change before
 * that.
 */
public abstract class KeySerializer<KeyT extends Key, SerializationT extends Serialization> {
  /**
   * A function which serializes a key.
   *
   * <p>This interface exists only so we have a type we can reference in {@link #create}. Users
   * should not use this directly; see the explanation in {@link #create}.
   */
  public interface KeySerializationFunction<
      KeyT extends Key, SerializationT extends Serialization> {
    SerializationT serializeKey(KeyT key, Optional<SecretKeyAccess> access)
        throws GeneralSecurityException;
  }

  private final Class<KeyT> keyClass;
  private final Class<SerializationT> serializationClass;

  private KeySerializer(Class<KeyT> keyClass, Class<SerializationT> serializationClass) {
    this.keyClass = keyClass;
    this.serializationClass = serializationClass;
  }

  public abstract SerializationT serializeKey(KeyT key, Optional<SecretKeyAccess> access)
      throws GeneralSecurityException;

  public Class<KeyT> getKeyClass() {
    return keyClass;
  }

  public Class<SerializationT> getSerializationClass() {
    return serializationClass;
  }

  /**
   * Creates a KeySerializer object.
   *
   * <p>In order to create a KeySerializer object, one typically writes a function
   *
   * <pre>{@code
   * class MyClass {
   *   private static MySerialization serialize(MyKey key, Optional<SecretKeyAccess> access)
   *             throws GeneralSecurityException {
   *     ...
   *   }
   * }
   * }</pre>
   *
   * This function can then be used to create a {@code KeySerializer}:
   *
   * <pre>{@code
   * KeySerializer<MyKey, MySerialization> serializer =
   *       KeySerializer.create(MyClass::serialize, MyKey.class, MySerialization.class);
   * }</pre>
   */
  public static <KeyT extends Key, SerializationT extends Serialization>
      KeySerializer<KeyT, SerializationT> create(
          KeySerializationFunction<KeyT, SerializationT> function,
          Class<KeyT> keyClass,
          Class<SerializationT> serializationClass) {
    return new KeySerializer<KeyT, SerializationT>(keyClass, serializationClass) {
      @Override
      public SerializationT serializeKey(KeyT key, Optional<SecretKeyAccess> access)
          throws GeneralSecurityException {
        return function.serializeKey(key, access);
      }
    };
  }
}
