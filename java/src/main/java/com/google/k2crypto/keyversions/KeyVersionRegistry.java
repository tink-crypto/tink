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
import com.google.k2crypto.exceptions.UnregisteredKeyVersionException;
import com.google.k2crypto.keyversions.KeyVersionProto.Type;
import com.google.protobuf.ExtensionRegistry;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A registry of available {@link KeyVersion} implementations.
 * 
 * <p>This class is thread-safe.
 *
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class KeyVersionRegistry {
  
  // Context for the current K2 session
  private final K2Context context;

  // Mapping of key version type to the registered (and verified) key version.
  private final Map<Type, RegisteredKeyVersion> keyVersions =
      new LinkedHashMap<KeyVersionProto.Type, RegisteredKeyVersion>();
  
  // Cached list of all registered key versions
  private List<RegisteredKeyVersion> cachedKeyVersionList;
  
  // Cached proto extension registry 
  private ExtensionRegistry cachedProtoExtensions;
  
  /**
   * Constructs a KeyVersionRegistry for the given context.
   * 
   * @param context Context of the current K2 session.
   */
  public KeyVersionRegistry(K2Context context) {
    this.context = context;
    invalidateCaches();
  }
  
  /**
   * Invalidates the cached data on the registry.
   * Must be called whenever the key version map changes.
   */
  private void invalidateCaches() {
    synchronized (keyVersions) {
      if (keyVersions.isEmpty()) {
        // Use empty default objects
        cachedKeyVersionList = Collections.emptyList();
        cachedProtoExtensions = ExtensionRegistry.getEmptyRegistry();
      } else {
        // Generate on demand
        cachedKeyVersionList = null;
        cachedProtoExtensions = null;
      }
    }
  }

  /**
   * Constructs a {@link KeyVersion.Builder} that will build a key version of
   * the specified type.
   * 
   * @param type Type to build.
   * 
   * @return a builder for the specified type.
   * 
   * @throws UnregisteredKeyVersionException if a key version implementation
   *     for the type has not been registered. 
   */
  public KeyVersion.Builder newBuilder(Type type)
      throws UnregisteredKeyVersionException {
    if (type == null) {
      throw new NullPointerException("type");
    }
    RegisteredKeyVersion regKeyVersion;
    synchronized (keyVersions) {
      regKeyVersion = keyVersions.get(type);
    }
    if (regKeyVersion == null) {
      throw new UnregisteredKeyVersionException(type);
    }
    return regKeyVersion.newBuilder();
  }
  
  /**
   * Returns whether a type has been registered.
   *  
   * @param type Type to check.
   * 
   * @return {@code true} if the type is registered, {@code false} otherwise.
   */
  public boolean isRegistered(Type type) {
    if (type == null) {
      throw new NullPointerException("type");
    }
    synchronized (keyVersions) {
      return keyVersions.containsKey(type);
    }
  }
  
  /**
   * Returns the registration information for the given type.
   * 
   * @param type Type to check.
   * 
   * @return the {@link RegisteredKeyVersion} object of the type, or null if
   *     the type has not been registered.
   */
  public RegisteredKeyVersion getRegistration(Type type) {
    if (type == null) {
      throw new NullPointerException("type");
    }
    synchronized (keyVersions) {
      return keyVersions.get(type);
    }    
  }
  
  /**
   * Returns a registry of protocol buffer extensions of all the currently
   * registered key versions.
   */
  public ExtensionRegistry getProtoExtensions() {
    synchronized (keyVersions) {
      ExtensionRegistry registry = cachedProtoExtensions;
      if (registry == null) {
        registry = ExtensionRegistry.newInstance();
        for (RegisteredKeyVersion rkv : getRegisteredKeyVersions()) {
          try {
            rkv.registerProtoExtensions(registry);
          } catch (ReflectiveOperationException ex) {
            // Might get this if the proto is broken. Just print trace and
            // continue.
            // TODO(darylseah): Perhaps log this? 
            ex.printStackTrace();
          }
        }
        registry = registry.getUnmodifiable();
        cachedProtoExtensions = registry;
      }
      return registry;
    }
  }
  
  /**
   * Registers a key version.
   * 
   * @param kvClass Class of the key version implementation to register.
   *                See {@link KeyVersion} for specifications.
   * 
   * @return {@link RegisteredKeyVersion} if successfully registered,
   *         {@code null} if a key version of the type is already registered.
   * 
   * @throws KeyVersionException if there is a problem with the key version
   *                             implementation.
   */
  public RegisteredKeyVersion register(Class<? extends KeyVersion> kvClass)
      throws KeyVersionException {
    if (kvClass == null) {
      throw new NullPointerException("kvClass");
    }

    RegisteredKeyVersion regKeyVersion =
        new RegisteredKeyVersion(context, kvClass);
    Type type = regKeyVersion.getType();
    
    synchronized (keyVersions) {
      if (keyVersions.containsKey(type)) {
        return null;
      }
      keyVersions.put(type, regKeyVersion);
      invalidateCaches();
    }
    return regKeyVersion;
  }
  
  /**
   * Unregisters a key version.
   * 
   * @param type Type of the key version to unregister.
   * 
   * @return {@code true} if successfully unregistered, {@code false} if no
   *         registered type exists.
   */
  public boolean unregister(Type type) {
    if (type == null) {
      throw new NullPointerException("type");
    }
    synchronized (keyVersions) {
      if (keyVersions.remove(type) != null) {
        invalidateCaches();
        return true;
      }
    }
    return false;
  }
  
  /**
   * Returns an immutable thread-safe list of the currently registered key
   * versions, in registration order.
   */
  public List<RegisteredKeyVersion> getRegisteredKeyVersions() {
    synchronized (keyVersions) {
      List<RegisteredKeyVersion> list = cachedKeyVersionList;
      if (list == null) {
        list = Collections.unmodifiableList(
            new ArrayList<RegisteredKeyVersion>(keyVersions.values()));
        cachedKeyVersionList = list;
      }
      return list;
    }
  }
}
