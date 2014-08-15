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

package com.google.k2crypto;

import com.google.k2crypto.KeyProto.KeyCore;
import com.google.k2crypto.KeyProto.KeyData;
import com.google.k2crypto.exceptions.BuilderException;
import com.google.k2crypto.exceptions.InvalidKeyDataException;
import com.google.k2crypto.exceptions.KeyModifierException;
import com.google.k2crypto.exceptions.UnregisteredKeyVersionException;
import com.google.k2crypto.keyversions.KeyVersion;
import com.google.k2crypto.keyversions.KeyVersionProto.KeyVersionData;
import com.google.k2crypto.keyversions.KeyVersionRegistry;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistry;
import com.google.protobuf.InvalidProtocolBufferException;

import java.util.ArrayList;
import java.util.List;

/**
 * This class represents a Key in K2. It holds a list of KeyVersions and a
 * reference to the primary KeyVersion.
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class Key {
  
  // Retained raw bytes of the core key information
  // (Cannot be changed once generated)
  private ByteString coreBytes = null;

  /**
   * The list of key versions
   */
  private ArrayList<KeyVersion> keyVersions = new ArrayList<KeyVersion>();

  /**
   * 
   */
  private KeyVersion primary;

  /**
   * Empty constructor - construct an empty Key
   */
  public Key() {}

  /**
   * Construct a Key with a single KeyVersion
   *
   * @param kv A KeyVersion to initialize the Key with
   */
  public Key(KeyVersion kv) {
    // Add the key version to the key
    this.keyVersions.add(kv);
    // set the primary to the key version (the only key version in the key)
    this.primary = kv;
  }

  /**
   * Construct a Key from protobuf data.
   * 
   * @param context Context of the K2 session.
   * @param data Protobuf data of the key.
   * 
   * @throws UnregisteredKeyVersionException if the data contains a key version
   *     type that has no registered implementation.
   * @throws InvalidKeyDataException if the protobuf data is invalid.
   */
  public Key(K2Context context, KeyData data)
      throws UnregisteredKeyVersionException, InvalidKeyDataException {
    
    // NOTE: lower-level exceptions take precedence by design
    
    KeyVersionRegistry registry = context.getKeyVersionRegistry();
    ExtensionRegistry protoRegistry = registry.getProtoExtensions();

    // Retain the core
    if (!data.hasCore()) {
      // Core field is required
      throw new InvalidKeyDataException(
          InvalidKeyDataException.Reason.PROTO_PARSE, null);
    }
    coreBytes = data.getCore();
    
    // Parse the core, containing the security/usage constraints
    KeyCore core;
    try {
      core = KeyCore.parseFrom(coreBytes, protoRegistry);
    } catch (InvalidProtocolBufferException ex) {
      throw new InvalidKeyDataException(
          InvalidKeyDataException.Reason.PROTO_PARSE, ex);
    }
    // TODO(darylseah): extract security properties from core

    // Extract the key version list
    final int kvCount = data.getKeyVersionCount();
    keyVersions.ensureCapacity(kvCount);

    UnregisteredKeyVersionException unregisteredException = null; 
    InvalidKeyDataException buildException = null;
    
    for (KeyVersionData kvData : data.getKeyVersionList()) {
      if (!kvData.hasType()) {
        // Type field is required
        throw new InvalidKeyDataException(
            InvalidKeyDataException.Reason.PROTO_PARSE, null);
      }
      try {
        KeyVersion kv = registry.newBuilder(kvData.getType())
            .withData(kvData, protoRegistry).build();
        keyVersions.add(kv);
      } catch (InvalidProtocolBufferException ex) {
        // Throw proto parsing exceptions immediately
        throw new InvalidKeyDataException(
            InvalidKeyDataException.Reason.PROTO_PARSE, ex);
      } catch (RuntimeException ex) {
        // We consider runtime exceptions to be parsing exceptions
        throw new InvalidKeyDataException(
            InvalidKeyDataException.Reason.PROTO_PARSE, ex);        
      } catch (BuilderException ex) {
        // Delay-throw builder exceptions...
        buildException = new InvalidKeyDataException(
            InvalidKeyDataException.Reason.KEY_VERSION_BUILD, ex);
      } catch (UnregisteredKeyVersionException ex) {
        // ...and unregistered key version exceptions
        unregisteredException = ex;
      }
    }

    // Unregistered key versions take precedence over build exceptions
    if (unregisteredException != null) {
      throw unregisteredException;
    } else if (buildException != null) {
      throw buildException;
    }
    
    // Extract the primary
    if (kvCount > 0) {
      int primaryIndex = (data.hasPrimary() ? data.getPrimary() : -1);
      if (primaryIndex < 0 || primaryIndex >= keyVersions.size()) {
        throw new InvalidKeyDataException(
            InvalidKeyDataException.Reason.CORRUPTED_PRIMARY, null);
      }
      primary = keyVersions.get(primaryIndex);      
    }
  }

  /**
   * Returns the raw bytes of the core data of the key.
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
   * Returns a builder for building the protobuf core of the key.
   * 
   * <p>The core contains all the security properties of the key.
   */
  protected KeyCore.Builder buildCore() {
    KeyCore.Builder builder = KeyCore.newBuilder();
    // TODO(darylseah): populate core with security properties
    return builder;
  }
  
  /**
   * Returns a builder for building the protobuf data of the key.
   * 
   * <p>The data contains the core as well as the key versions in the key.
   */
  public KeyData.Builder buildData() {
    KeyData.Builder builder = KeyData.newBuilder();
    builder.setCore(getCore());
    List<KeyVersion> keyVersions = this.keyVersions;
    final int size = keyVersions.size();
    for (int i = 0; i < size; ++i) {
      KeyVersion kv = keyVersions.get(i);
      builder.addKeyVersion(kv.buildData());
      if (kv == primary) {
        builder.setPrimary(i);
      }
    }
    if (size > 0 && !builder.hasPrimary()) {
      throw new AssertionError("Corrupted key state.");
    }
    return builder;
  }
  
  /**
   * Method to add a KeyVersion to this Key
   *
   * @param keyVersion
   */
  protected void addKeyVersion(KeyVersion keyVersion) {
    // TODO: duplicate checking
    this.keyVersions.add(keyVersion);
    // If there is only one keyversion in the key, set it as the primary
    if (this.keyVersions.size() == 1) {
      this.primary = keyVersion;
    }
  }

  /**
   * Method to obtain the primary KeyVersion in this Key
   *
   * @return the primary KeyVersion in this Key
   */
  protected KeyVersion getPrimary() {
    return this.primary;
  }

  /**
   * Method to get the number of key versions in this key
   *
   * @return the number of key versions in this key
   */
  protected int getKeyVersionsCount() {
    return this.keyVersions.size();
  }

  /**
   * Sets a given keyversion as the primary in the key
   *
   * @param keyversion the keyversion to set as the primary
   */
  protected void setPrimary(KeyVersion keyversion) {
    // TODO: check that the primary keyversion is in the list 
    this.primary = keyversion;

  }

  /**
   * Removes a given keyversion from the key
   *
   * @param keyversion the keyversion to remove from the key
   * @throws KeyModifierException
   */
  protected void removeKeyVersion(KeyVersion keyversion)
      throws KeyModifierException {
    if (!keyVersions.contains(keyversion)) {
      throw new KeyModifierException(
          "Given KeyVersion is not in the Key");
    } else if (this.primary == keyversion) {
      throw new KeyModifierException(
          "Cannot remove KeyVersion as it is the primary in the Key");
    } else {
      this.keyVersions.remove(keyversion);
    }
  }

  /**
   * Check if the Key contains a given KeyVersion
   *
   * @param keyversion The KeyVersion to check if it is in the Key
   * @return Returns true if and only if keyversion is in this Key
   */
  protected boolean containsKeyVersion(KeyVersion keyversion) {
    return this.keyVersions.contains(keyversion);
  }
}
