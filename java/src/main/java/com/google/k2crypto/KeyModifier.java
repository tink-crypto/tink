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

import com.google.k2crypto.exceptions.BuilderException;
import com.google.k2crypto.exceptions.KeyModifierException;
import com.google.k2crypto.keyversions.AESKeyVersion;
import com.google.k2crypto.keyversions.KeyVersion;

/**
 * This class represents a Key modifier in K2. It allows you to create a Key, create KeyVersions and
 * add them to the Key, and set a KeyVersion as primary in Key
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class KeyModifier {

  /**
   * The Key object that this class modifies
   */
  private Key key = new Key();

  /**
   * Return the Key for this key modifier
   *
   * @return The Key that this key modifier can modify
   */
  protected Key getKey() {
    return this.key;
  }

  /**
   * Method to create a KeyVersion and add it to the Key
   *
   * @return The KeyVersion we just added to the Key
   * @throws BuilderException
   */
  public KeyVersion addKeyVersion() throws BuilderException {
    /**
     * TODO: Update this to support multiple key versions
     */
    // Create a new KeyVersion
    AESKeyVersion keyversion = new AESKeyVersion.Builder().build();

    // now add it to the Key
    key.addKeyVersion(keyversion);

    // return the key version we just added to the Key
    return keyversion;
  }

  /**
   * Method to get the primary KeyVersion from the Key
   *
   * @return the primary KeyVersion from the Key
   */
  public KeyVersion getPrimary() {
    return key.getPrimary();
  }

  /**
   * Method to get the number of KeyVersions in the Key
   *
   * @return the number of KeyVersions in the Key
   */
  public Object getKeyVersionsCount() {
    return key.getKeyVersionsCount();
  }

  /**
   * Sets a given keyversion as the primary in the key
   *
   * @param keyversion the keyversion to set as the primary
   */
  public void setPrimary(KeyVersion keyversion) {
    key.setPrimary(keyversion);

  }

  /**
   * Removes a given keyversion from the key
   *
   * @param keyversion the keyversion to remove from the key
   * @throws KeyModifierException
   */
  public void removeKeyVersion(KeyVersion keyversion) throws KeyModifierException {
    key.removeKeyVersion(keyversion);

  }

  /**
   * Check if the Key contains a given KeyVersion
   *
   * @param keyversion The KeyVersion to check if it is in the Key
   * @return Returns true if and only if keyversion is in the Key that this KeyModifier refers to
   */
  public boolean containsKeyVersion(KeyVersion keyversion) {
    return key.containsKeyVersion(keyversion);
  }

  /**
   * Method to add a given keyversion to the key
   *
   * @param keyversion The keyversion to add to the key
   */
  public void addKeyVersion(KeyVersion keyversion) {
    key.addKeyVersion(keyversion);
  }
}
