// Copyright 2023 Google LLC
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

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.proto.KeyData;
import java.security.GeneralSecurityException;

/**
 * Abstract class representing the real configuration API, i.e. all algorithms that Tink
 * understands. Internal. Users should not access these methods since the operations are to be used
 * by internal KeysetHandle operations only.
 */
public abstract class InternalConfiguration extends Configuration {
  /**
   * Creates a primitive from a key in the old (proto) format.
   */
  public abstract <P> P getLegacyPrimitive(KeyData keyData, Class<P> primitiveClass)
      throws GeneralSecurityException;

  /**
   * Given a key and a desired primitive class, creates the required primitive.
   */
  public abstract <P> P getPrimitive(Key key, Class<P> primitiveClass)
      throws GeneralSecurityException;

  /**
   * Wraps the primitives in the primitive set into the provided class.
   *
   * @throws GeneralSecurityException if the wrapper for the provided pair
   * (input class, wrapped class) is not registered
   */
  public abstract <B, P> P wrap(PrimitiveSet<B> primitiveSet, Class<P> clazz)
      throws GeneralSecurityException;

  /**
   * Given the target class, reveals primitive set of what type should be provided to the
   * {@link InternalConfiguration.wrap} method in order to get a wrapped object of the target class.
   */
  public abstract Class<?> getInputPrimitiveClass(Class<?> wrapperClassObject)
      throws GeneralSecurityException;

  public static InternalConfiguration createFromPrimitiveRegistry(PrimitiveRegistry registry) {
    return new InternalConfigurationImpl(registry);
  }

  /**
   * Implementation of the configuration API.
   */
  private static class InternalConfigurationImpl extends InternalConfiguration {
    /**
     * Immutable registry instance.
     */
    private final PrimitiveRegistry registry;

    private InternalConfigurationImpl(PrimitiveRegistry registry) {
      this.registry = registry;
    }

    @Override
    public <P> P getLegacyPrimitive(KeyData keyData, Class<P> primitiveClass)
        throws GeneralSecurityException {
      throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public <P> P getPrimitive(Key key, Class<P> primitiveClass) throws GeneralSecurityException {
      return registry.getPrimitive(key, primitiveClass);
    }

    @Override
    public Class<?> getInputPrimitiveClass(Class<?> wrapperClassObject)
        throws GeneralSecurityException {
      return registry.getInputPrimitiveClass(wrapperClassObject);
    }

    @Override
    public <B, P> P wrap(PrimitiveSet<B> primitiveSet, Class<P> clazz)
        throws GeneralSecurityException {
      return registry.wrap(primitiveSet, clazz);
    }
  }
}
