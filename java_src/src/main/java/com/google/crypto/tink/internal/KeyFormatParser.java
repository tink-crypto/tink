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
 * Parses {@code Serialization} objects into {@code KeyFormat} objects of a certain kind.
 *
 * <p>This class should eventually be in Tinks public API -- however, it might still change before
 * that.
 */
public abstract class KeyFormatParser<SerializationT extends Serialization> {
  /**
   * A function which parses a KeyFormat object.
   *
   * <p>This interface exists only so we have a type we can reference in {@link #create}. Users
   * should not use this directly; see the explanation in {@link #create}.
   */
  public interface KeyFormatParsingFunction<SerializationT extends Serialization> {
    KeyFormat parseKeyFormat(SerializationT serialization) throws GeneralSecurityException;
  }

  private final ByteArray objectIdentifier;
  private final Class<SerializationT> serializationClass;

  private KeyFormatParser(ByteArray objectIdentifier, Class<SerializationT> serializationClass) {
    this.objectIdentifier = objectIdentifier;
    this.serializationClass = serializationClass;
  }

  /**
   * Parses a serialization into a KeyFormat.
   *
   * <p>This function is usually called with a Serialization matching the result of {@link
   * getObjectIdentifier}. However, implementations should check that this is the case.
   */
  public abstract KeyFormat parseKeyFormat(SerializationT serialization)
      throws GeneralSecurityException;

  /**
   * Returns the {@code objectIdentifier} for this serialization.
   *
   * <p>The object identifier is a unique identifier per registry for this object (in the standard
   * proto serialization, it is the typeUrl). In other words, when registering a {@code
   * KeyFormatParser}, the registry will invoke this to get the handled object identifier. In order
   * to parse an object of type {@code SerializationT}, the registry will then obtain the {@code
   * objectIdentifier} of this serialization object, and call the parser corresponding to this
   * object.
   */
  public final ByteArray getObjectIdentifier() {
    return objectIdentifier;
  }

  public final Class<SerializationT> getSerializationClass() {
    return serializationClass;
  }

  /**
   * Creates a KeyFormatParser object.
   *
   * <p>In order to create a KeyFormatParser object, one typically writes a function
   *
   * <pre>{@code
   * class MyClass {
   *   private static MyKeyFormat parse(MySerialization keyFormatSerialization)
   *             throws GeneralSecurityException {
   *     ...
   *   }
   * }
   * }</pre>
   *
   * This function can then be used to create a {@code KeyFormatParser}:
   *
   * <pre>{@code
   * KeyFormatParser<MySerialization> parser =
   *       KeyFormatParser.create(MyClass::parse, objectIdentifier, MySerialization.class);
   * }</pre>
   *
   * @param function The function used to parse a KeyFormat
   * @param objectIdentifier The identifier to be returned by {@link #getObjectIdentifier}
   * @param serializationClass The class object corresponding to {@code SerializationT}
   */
  public static <SerializationT extends Serialization> KeyFormatParser<SerializationT> create(
      KeyFormatParsingFunction<SerializationT> function,
      ByteArray objectIdentifier,
      Class<SerializationT> serializationClass) {
    return new KeyFormatParser<SerializationT>(objectIdentifier, serializationClass) {
      @Override
      public KeyFormat parseKeyFormat(SerializationT serialization)
          throws GeneralSecurityException {
        return function.parseKeyFormat(serialization);
      }
    };
  }
}
