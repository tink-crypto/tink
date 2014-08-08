// Copyright 2014 Google. Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.k2crypto.keyversions;

import com.google.k2crypto.K2Context;
import com.google.k2crypto.exceptions.KeyVersionException;
import com.google.k2crypto.keyversions.KeyVersion.Builder;
import com.google.k2crypto.keyversions.KeyVersionProto.Type;
import com.google.protobuf.ExtensionRegistry;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/**
 * A key version implementation (class) that has been registered with K2.
 *  
 * <p>This class is thread-safe.
 *
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class RegisteredKeyVersion {
  
  // Context for the current K2 session
  private final K2Context context;

  // Class of the registered key version implementation
  private final Class<? extends KeyVersion> keyVersionClass;
  
  // Builder constructor derived from the KeyVersion class
  private final Constructor<? extends Builder> builderConstructor;
  
  // Derived method that will register all proto extensions for the key version
  private final Method registerProtoExtensions;
  
  // Meta-data annotation on the KeyVersion class
  private final KeyVersionInfo info;
  
  /**
   * Constructs a registered key version from a class and verifies that it
   * conforms to the expected structure.
   * 
   * @param context Context for the K2 session.
   * @param kvClass Class of the key version implementation.
   * 
   * @throws KeyVersionException if the key version class does not conform.
   */
  RegisteredKeyVersion(K2Context context, Class<? extends KeyVersion> kvClass)
      throws KeyVersionException {
    if (context == null) {
      throw new NullPointerException("context");
    } else if (kvClass == null) {
      throw new NullPointerException("kvClass");
    }
    
    this.context = context;
    this.keyVersionClass = kvClass;

    // Check the Builder class
    try {
      Class<?> builder = Class.forName(
          kvClass.getName() + "$Builder", true, kvClass.getClassLoader());
      
      if (!Builder.class.isAssignableFrom(builder)) {
        // The builder class does not extend KeyVersion.Builder
        throw new KeyVersionException(
            kvClass, KeyVersionException.Reason.BAD_PARENT);
      } else if (!kvClass.isAssignableFrom(
          builder.getMethod("build").getReturnType())) {
        // There is no build() method returning the key version type
        throw new KeyVersionException(
            kvClass, KeyVersionException.Reason.BAD_BUILD);        
      }

      // The following constructor extraction is reflectively type checked
      @SuppressWarnings("unchecked")
      Constructor<? extends Builder> constructor =
          (Constructor<? extends Builder>)builder.getDeclaredConstructor();
      
      // Constructor can only throw Errors or RuntimeExceptions
      for (Class<?> exClass : constructor.getExceptionTypes()) {
        if (!RuntimeException.class.isAssignableFrom(exClass)
            && !Error.class.isAssignableFrom(exClass)) {
          throw new KeyVersionException(
              kvClass, KeyVersionException.Reason.ILLEGAL_THROWS);
        }
      }

      // Check that the builder can instantiate (should not be much overhead)
      constructor.newInstance();
      builderConstructor = constructor;
      
    } catch (ClassNotFoundException ex) {
      // The builder class was not found
      throw new KeyVersionException(
          kvClass, KeyVersionException.Reason.NO_BUILDER);
    } catch (NoSuchMethodException ex) {
      // This exception should only be thrown by the constructor check
      // (and not the build method check). 
      throw new KeyVersionException(
          kvClass, KeyVersionException.Reason.NO_CONSTRUCTOR);
    } catch (ReflectiveOperationException ex) {
      // Builder instantiation test failed
      throw new KeyVersionException(
          kvClass, KeyVersionException.Reason.INSTANTIATE_FAIL);
    }
    
    // Check the info annotation
    info = kvClass.getAnnotation(KeyVersionInfo.class);
    if (info == null) {
      throw new KeyVersionException(
          kvClass, KeyVersionException.Reason.NO_METADATA);
    }
    
    // What we really need is the static registerAllExtensions() method on the
    // generated proto. We cannot verify that the proto really belongs to
    // the key version (or that it really is a generated proto). 
    try {
      registerProtoExtensions = info.proto()
          .getMethod("registerAllExtensions", ExtensionRegistry.class);
      if (!Modifier.isStatic(registerProtoExtensions.getModifiers())) {
        throw new KeyVersionException(
            kvClass, KeyVersionException.Reason.BAD_PROTO);
      }
    } catch (NoSuchMethodException ex) {
      throw new KeyVersionException(
          kvClass, KeyVersionException.Reason.BAD_PROTO);
    }
  }

  /**
   * Returns the context used when the key version was registered.
   */
  K2Context getContext() {
    return context;
  }

  /**
   * Instantiates a Builder for building the key version.
   */
  Builder newBuilder() {
    try {
      // Use reflection to instantiate the builder
      return builderConstructor.newInstance();
    } catch (InvocationTargetException ex) {
      Throwable t = ex.getCause();
      // Re-throw throwables that do not need an explicit catch. (This should
      // not actually happen unless the builder has a flaky constructor.)
      if (t instanceof Error) {
        throw (Error)t;
      } else if (t instanceof RuntimeException) {
        throw (RuntimeException)t;
      } else {
        // This should not happen, owing to construction-time checks.
        throw new AssertionError("Should not happen!", t);
      }
    } catch (ReflectiveOperationException ex) {
      // Should not happen because we test instantiate in the constructor...
      throw new AssertionError("Should not happen!", ex);
    }
  }
  
  /**
   * Registers all proto extensions required by the key version.
   * 
   * @param registry Proto extension registry to use.
   * 
   * @throws ReflectiveOperationException if something goes wrong with
   *     reflectively calling the method on the generated proto.
   */
  void registerProtoExtensions(ExtensionRegistry registry)
      throws ReflectiveOperationException {
    try {
      registerProtoExtensions.invoke(null, registry);
    } catch (RuntimeException ex) {
      throw new ReflectiveOperationException(ex);
    }
  }
  
  /**
   * Returns the proto type of the key version.
   */
  public Type getType() {
    return info.type();
  }
  
  /**
   * Returns the class implementing the key version. 
   */
  public Class<? extends KeyVersion> getKeyVersionClass() {
    return keyVersionClass;
  }
  
  /**
   * Returns the builder class for the key version. 
   */
  public Class<? extends Builder> getBuilderClass() {
    return builderConstructor.getDeclaringClass();
  }
  
  /**
   * Returns the generated protocol buffer class for the key version.
   */
  public Class<?> getProtoClass() {
    return info.proto();
  }
  
  /**
   * Returns the hash-code for the registered key version, which is the hash
   * of the key version class.
   */
  @Override
  public int hashCode() {
    return keyVersionClass.hashCode();
  }
  
  /**
   * Tests the registered key version for equality with an object.
   * 
   * @param obj Object to compare to.
   * 
   * @return {@code true} if, and only if, the object is also a
   *         RegisteredKeyVersion and it has the same key version class and
   *         context as this one. 
   */
  @Override
  public boolean equals(Object obj) {
    if (obj instanceof RegisteredKeyVersion) {
      RegisteredKeyVersion other = (RegisteredKeyVersion)obj;
      return other.keyVersionClass.equals(keyVersionClass)
          && other.context.equals(context);
    }
    return false;
  }
  
  /**
   * @see Object#toString()
   */
  @Override
  public String toString() {
    return info.type().name() + ":" + keyVersionClass.getName();
  }
}
