/*
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.google.k2crypto.keyversions;

import com.google.k2crypto.exceptions.BuilderException;
import com.google.k2crypto.keyversions.KeyVersionProto.KeyVersionCore;
import com.google.k2crypto.keyversions.KeyVersionProto.KeyVersionData;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistry;
import com.google.protobuf.InvalidProtocolBufferException;

/**
 * This class represents a KeyVersion in K2. It is abstract and extended by
 * specific key implementations such as SymmetricKey which is extended by AESKey
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public abstract class KeyVersion {
  
  // Retained raw bytes of the core key version material
  // (Cannot be changed once generated)
  private ByteString coreBytes = null;
  
  // Key version identifier (a hash of the core)
  private ByteString id = null;

  /**
   * Initializes the KeyVersion.
   * 
   * @param builder Builder, possibly with serialized data.
   */
  protected KeyVersion(Builder builder) {
    KeyVersionData data = builder.kvData;
    if (data != null) {
      // Extract the core (important stuff) 
      coreBytes = data.getCore();
      // Extract other fields if necessary
    }
  }

  /**
   * Returns the identifier of the key version. 
   */
  public final ByteString getId() {
    ByteString id = this.id;
    if (id == null) {
      ByteString core = getCore();
      // TODO(darylseah): Hash the core and produce the ID
      //                  (Right now, ID === core).
      // TODO(darylseah): Also, figure out how to pull in security properties
      //                  from the Key into the hash
      this.id = id = core;
    }
    return id;
  }
  
  /**
   * Returns the raw bytes of the core data of the key version.
   * Will invoke {@link #buildCore()} to generate it if needed.
   */
  protected final ByteString getCore() {
    ByteString core = coreBytes;
    if (core == null) {
      core = buildCore().build().toByteString();
      coreBytes = core;
    }
    return core;
  }
  
  /**
   * Returns a builder for building the protobuf core of the key version.
   * 
   * <p>The core consists of the essential fields of the KeyVersion that will
   * be factored into the hash identifier. This method should be overridden by
   * subclasses to add their own extension to the core.
   */
  protected KeyVersionCore.Builder buildCore() {
    KeyVersionCore.Builder builder = KeyVersionCore.newBuilder();
    return builder;
  }
  
  /**
   * Returns a builder for building the protobuf data of the key version.
   * 
   * <p>The data is the overall package that needs to be saved to persist
   * the KeyVersion and includes the core. This method should be overridden by
   * subclasses to add their own extension to the data.
   */
  public KeyVersionData.Builder buildData() {
    KeyVersionData.Builder builder = KeyVersionData.newBuilder();
    builder.setType(getClass().getAnnotation(KeyVersionInfo.class).type());
    builder.setCore(getCore());
    return builder;
  }
  
  /**
   * Returns the hash code for the key version, which is a function of the
   * computed identifier.
   */
  @Override
  public int hashCode() {
    return getId().hashCode();
  }
  
  /**
   * Tests the key version for equality with an object.
   * 
   * @param obj Object to compare to.
   * 
   * @return {@code true} if, and only if, the object is of the same class and
   *         has the same core bytes as this one. 
   */
  @Override
  public boolean equals(Object obj) {
    return obj != null && getClass().equals(obj.getClass())
        && getCore().equals(((KeyVersion)obj).getCore());
  }
  
  /**
   * 
   * This class represents an abstract key version builder. It is extended by other classes to allow
   * you to build specific key versions (for example AESKeyVersionBuilder)
   *
   * @author John Maheswaran (maheswaran@google.com)
   */
  public static abstract class Builder {
    
    // Data of the key version (non-null only if we are deserializing)
    private KeyVersionData kvData;
    
    /**
     * Initializes the builder with protobuf data. The core will be parsed
     * from the data and the protobuf extension registry is required for this.
     * 
     * <p>Should be overridden by sub-classes to pull version-specific fields
     * from the data to the builder.  
     *     
     * @param kvData Data of the key version.
     * @param registry Registry of all protobuf extensions for key versions.
     * 
     * @throws InvalidProtocolBufferException if the data could not be parsed,
     *     e.g. it is not formatted correctly or a required field is missing.
     */
    public Builder withData(KeyVersionData kvData, ExtensionRegistry registry)
        throws InvalidProtocolBufferException {
      if (kvData == null) {
        throw new NullPointerException("kvData");
      } else if (!kvData.hasCore()) {
        // Core field is required
        throw new InvalidProtocolBufferException("No core.");
      }
      withCore(KeyVersionCore.parseFrom(kvData.getCore(), registry));
      this.kvData = kvData;
      return this;
    }
    
    /**
     * Initializes the builder with protobuf core.
     * 
     * <p>Should be overridden by sub-classes to pull version-specific fields
     * from the core to the builder.  
     *     
     * @param kvCore Core of the key version.
     * 
     * @throws InvalidProtocolBufferException if the core could not be parsed,
     *     e.g. it is not formatted correctly or a required field is missing.
     */
    protected Builder withCore(KeyVersionCore kvCore)
        throws InvalidProtocolBufferException {
      if (kvCore == null) {
        throw new NullPointerException("kvCore");
      }
      return this;
    }
    
    /**
     * Builds the KeyVersion with the arguments set from the builder.
     *   
     * @throws BuilderException if there is a problem building the KeyVersion.
     */
    public abstract KeyVersion build() throws BuilderException;
  }
}
