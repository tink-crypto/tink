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

import com.google.crypto.tink.Parameters;
import java.security.GeneralSecurityException;

/**
 * Serializes {@code Parameters} objects into {@code Serialization} objects of a certain kind.
 *
 * <p>This class should eventually be in Tinks public API -- however, it might still change before
 * that.
 */
public abstract class KeyFormatSerializer<
    ParametersT extends Parameters, SerializationT extends Serialization> {
  /**
   * A function which serializes a Parameters object.
   *
   * <p>This interface exists only so we have a type we can reference in {@link #create}. Users
   * should not use this directly; see the explanation in {@link #create}.
   */
  public interface KeyFormatSerializationFunction<
      ParametersT extends Parameters, SerializationT extends Serialization> {
    SerializationT serializeKeyFormat(ParametersT key) throws GeneralSecurityException;
  }

  private final Class<ParametersT> parametersClass;
  private final Class<SerializationT> serializationClass;

  private KeyFormatSerializer(
      Class<ParametersT> parametersClass, Class<SerializationT> serializationClass) {
    this.parametersClass = parametersClass;
    this.serializationClass = serializationClass;
  }

  public abstract SerializationT serializeKeyFormat(ParametersT parameters)
      throws GeneralSecurityException;

  public Class<ParametersT> getParametersClass() {
    return parametersClass;
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
   *   private static MySerialization serializeParameters(MyParameters Parameters)
   *             throws GeneralSecurityException {
   *     ...
   *   }
   * }
   * }</pre>
   *
   * This function can then be used to create a {@code KeyFormatSerializer}:
   *
   * <pre>{@code
   * KeyFormatSerializer<MyParameters, MySerialization> serializer =
   *       KeyFormatSerializer.create(MyClass::serializeParameters, MyParameters.class,
   *                                  MySerialization.class);
   * }</pre>
   */
  public static <ParametersT extends Parameters, SerializationT extends Serialization>
      KeyFormatSerializer<ParametersT, SerializationT> create(
          KeyFormatSerializationFunction<ParametersT, SerializationT> function,
          Class<ParametersT> parametersClass,
          Class<SerializationT> serializationClass) {
    return new KeyFormatSerializer<ParametersT, SerializationT>(
        parametersClass, serializationClass) {
      @Override
      public SerializationT serializeKeyFormat(ParametersT parameters)
          throws GeneralSecurityException {
        return function.serializeKeyFormat(parameters);
      }
    };
  }
}
