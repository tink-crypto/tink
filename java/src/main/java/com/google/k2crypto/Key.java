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

import com.google.k2crypto.exceptions.KeyModifierException;
import com.google.k2crypto.keyversions.KeyVersion;

import java.util.ArrayList;

/**
 * This class represents a Key in K2. It holds a list of KeyVersions and a reference to the primary
 * KeyVersion.
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class Key {
  /**
   * The list of key versions
   */
  private ArrayList<KeyVersion> keyVersions = new ArrayList<KeyVersion>();

  /**
   * 
   */
  private KeyVersion primary;

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
   * Method to add a KeyVersion to this Key
   *
   * @param keyVersion
   */
  protected void addKeyVersion(KeyVersion keyVersion) {
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
   * Empty constructor - construct an empty Key
   */
  public Key() {

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
    this.primary = keyversion;

  }

  /**
   * Removes a given keyversion from the key
   *
   * @param keyversion the keyversion to remove from the key
   * @throws KeyModifierException
   */
  protected void removeKeyVersion(KeyVersion keyversion) throws KeyModifierException {
    if (!keyVersions.contains(keyversion)) {
      throw new KeyModifierException("Given KeyVersion is not in the Key");
    } else if (this.primary == keyversion) {
      throw new KeyModifierException("Cannot remove KeyVersion as it is the primary in the Key");
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
