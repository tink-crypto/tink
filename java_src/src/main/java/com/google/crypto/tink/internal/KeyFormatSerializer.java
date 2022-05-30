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

import com.google.crypto.tink.KeyFormat;
import java.security.GeneralSecurityException;

/**
 * Serializes {@code KeyFormat} objects into {@code Serialization} objects of a certain kind.
 *
 * <p>This class should eventually be in Tinks public API -- however, it might still change before
 * that.
 */
public abstract class KeyFormatSerializer<
    KeyFormatT extends KeyFormat, SerializationT extends Serialization> {
  /**
   * A function which serializes a KeyFormat object.
   *
   * <p>This interface exists only so we have a type we can reference in {@link #create}. Users
   * should not use this directly; see the explanation in {@link #create}.
   */
  public interface KeyFormatSerializationFunction<
      KeyFormatT extends KeyFormat, SerializationT extends Serialization> {
    SerializationT serializeKeyFormat(KeyFormatT key) throws GeneralSecurityException;
  }

  private final Class<KeyFormatT> keyFormatClass;
  private final Class<SerializationT> serializationClass;

  private KeyFormatSerializer(
      Class<KeyFormatT> keyFormatClass, Class<SerializationT> serializationClass) {
    this.keyFormatClass = keyFormatClass;
    this.serializationClass = serializationClass;
  }

  public abstract SerializationT serializeKeyFormat(KeyFormatT keyFormat)
      throws GeneralSecurityException;

  public Class<KeyFormatT> getKeyFormatClass() {
    return keyFormatClass;
  }

  public Class<SerializationT> getSerializationClass() {
    return serializationClass;
  }

  /**
   * Creates a KeyFormatSerializer object.
   *
   * <p>In order to create a KeyFormatSerializer object, one typically writes a function
   *
   * <pre>{@code
   * class MyClass {
   *   private static MySerialization serializeKeyFormat(MyKeyFormat keyFormat)
   *             throws GeneralSecurityException {
   *     ...
   *   }
   * }
   * }</pre>
   *
   * This function can then be used to create a {@code KeyFormatSerializer}:
   *
   * <pre>{@code
   * KeyFormatSerializer<MyKeyFormat, MySerialization> serializer =
   *       KeyFormatSerializer.create(MyClass::serializeKeyFormat, MyKeyFormat.class,
   *                                  MySerialization.class);
   * }</pre>
   */
  public static <KeyFormatT extends KeyFormat, SerializationT extends Serialization>
      KeyFormatSerializer<KeyFormatT, SerializationT> create(
          KeyFormatSerializationFunction<KeyFormatT, SerializationT> function,
          Class<KeyFormatT> keyFormatClass,
          Class<SerializationT> serializationClass) {
    return new KeyFormatSerializer<KeyFormatT, SerializationT>(keyFormatClass, serializationClass) {
      @Override
      public SerializationT serializeKeyFormat(KeyFormatT keyFormat)
          throws GeneralSecurityException {
        return function.serializeKeyFormat(keyFormat);
      }
    };
  }
}
