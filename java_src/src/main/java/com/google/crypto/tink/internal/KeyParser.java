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
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;
import java.util.Optional;

/**
 * Parses {@code Serialization} objects into {@code Key} objects of a certain kind.
 *
 * <p>This class should eventually be in Tinks public API -- however, it might still change before
 * that.
 */
public abstract class KeyParser<SerializationT extends Serialization> {
  /**
   * A function which parses a key.
   *
   * <p>This interface exists only so we have a type we can reference in {@link #create}. Users
   * should not use this directly; see the explanation in {@link #create}.
   */
  public interface KeyParsingFunction<SerializationT extends Serialization> {
    Key parseKey(SerializationT serialization, Optional<SecretKeyAccess> access)
        throws GeneralSecurityException;
  }

  private final Bytes objectIdentifier;
  private final Class<SerializationT> serializationClass;

  private KeyParser(Bytes objectIdentifier, Class<SerializationT> serializationClass) {
    this.objectIdentifier = objectIdentifier;
    this.serializationClass = serializationClass;
  }

  /**
   * Parses a serialization into a key.
   *
   * <p>This function is usually called with a Serialization matching the result of {@link
   * getObjectIdentifier}. However, implementations should check that this is the case.
   */
  public abstract Key parseKey(SerializationT serialization, Optional<SecretKeyAccess> access)
      throws GeneralSecurityException;

  /**
   * Returns the {@code objectIdentifier} for this serialization.
   *
   * <p>The object identifier is a unique identifier per registry for this object (in the standard
   * proto serialization, it is the typeUrl). In other words, when registering a {@code KeyParser},
   * the registry will invoke this to get the handled object identifier. In order to parse an object
   * of type {@code SerializationT}, the registry will then obtain the {@code objectIdentifier} of
   * this serialization object, and call the parser corresponding to this object.
   */
  public final Bytes getObjectIdentifier() {
    return objectIdentifier;
  }

  public final Class<SerializationT> getSerializationClass() {
    return serializationClass;
  }

  /**
   * Creates a KeyParser object.
   *
   * <p>In order to create a KeyParser object, one typically writes a function
   *
   * <pre>{@code
   * class MyClass {
   *   private static MyKey parse(MySerialization key, Optional<SecretKeyAccess> access)
   *             throws GeneralSecurityException {
   *     ...
   *   }
   * }
   * }</pre>
   *
   * This function can then be used to create a {@code KeyParser}:
   *
   * <pre>{@code
   * KeyParser<MyKey, MySerialization> parser =
   *       KeyParser.create(MyClass::parse, objectIdentifier, MySerialization.class);
   * }</pre>
   *
   * Note that calling this function twice will result in objects which are not equal according to
   * {@code Object.equals}, and hence cannot be used to re-register a previously registered object.
   *
   * @param function The function used to parse a Key
   * @param objectIdentifier The identifier to be returned by {@link #getObjectIdentifier}
   * @param serializationClass The class object corresponding to {@code SerializationT}
   */
  public static <SerializationT extends Serialization> KeyParser<SerializationT> create(
      KeyParsingFunction<SerializationT> function,
      Bytes objectIdentifier,
      Class<SerializationT> serializationClass) {
    return new KeyParser<SerializationT>(objectIdentifier, serializationClass) {
      @Override
      public Key parseKey(SerializationT serialization, Optional<SecretKeyAccess> access)
          throws GeneralSecurityException {
        return function.parseKey(serialization, access);
      }
    };
  }
}
