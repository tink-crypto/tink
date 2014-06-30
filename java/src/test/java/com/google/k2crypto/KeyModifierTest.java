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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import com.google.k2crypto.exceptions.BuilderException;
import com.google.k2crypto.exceptions.KeyModifierException;
import com.google.k2crypto.keyversions.KeyVersion;

import org.junit.Test;

/**
 * This class tests using the KeyModifier class to modify a Key.
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class KeyModifierTest {

  /**
   * Test that the Key Modifier only creates a single Key object and always uses this
   */
  @Test
  public void testSingletonKey() {
    KeyModifier keyMod = new KeyModifier();
    Key key1 = keyMod.getKey();
    Key key2 = keyMod.getKey();
    assertSame(key1, key2);
  }

  /**
   * Test the method that creates a new KeyVersion and adds it to the Key
   * @throws BuilderException 
   */
  @Test
  public void testCreateAddKeyVersionToKey() throws BuilderException {
    // create a key modifier
    KeyModifier keymod = new KeyModifier();
    // create a new KeyVersion and add it to the Key
    KeyVersion keyversion = keymod.addKeyVersion();
    // get the primary key version from the Key using the KeyModifier
    KeyVersion primary = keymod.getPrimary();
    // check that the primary key version is equal to the key version we created and added to the
    // Key
    assertEquals(keyversion, primary);
  }

  /**
   * Test the method that adds KeyVersions to the Key and checks that many KeyVersions have been
   * added to the Key
   * @throws BuilderException 
   */
  @Test
  public void testAddKeyVersionsToKey() throws BuilderException {
    // create a key modifier
    KeyModifier keymod = new KeyModifier();

    // Add ten KeyVersions to the Key
    int numKeyVersions = 10;
    for (int i = 0; i < numKeyVersions; i++) {
      keymod.addKeyVersion();
    }
    // now check there are that many KeyVersion in the Key
    assertEquals(numKeyVersions, keymod.getKeyVersionsCount());

  }


  /**
   * Test the method that adds as specific KeyVersion to the Key
   * @throws BuilderException 
   * @throws KeyModifierException 
   */
  @Test
  public void testAddOneKeyVersionToKey() throws BuilderException, KeyModifierException {
    // create a key modifier
    KeyModifier keymod = new KeyModifier();

    // create and add a KeyVersion and add it to the Key
    KeyVersion keyversion1 = keymod.addKeyVersion();

    // create and add another KeyVersion and add it to the Key
    KeyVersion keyversion2 = keymod.addKeyVersion();
    
    // Set the second key version as primary
    keymod.setPrimary(keyversion2);
    
    // remove the first keyversion from the key
    keymod.removeKeyVersion(keyversion1);
    
    // check that the key does not contain the first key version
    assertFalse(keymod.containsKeyVersion(keyversion1));
    
   // now add the keyversion1 back to the Key
    keymod.addKeyVersion(keyversion1);
    
    // check that the key DOES contain the new key version
    assertTrue(keymod.containsKeyVersion(keyversion1));
  }

  /**
   * Test the method that removes a specific KeyVersion from the Key
   * @throws BuilderException 
   * @throws KeyModifierException 
   */
  @Test
  public void testRemoveKeyVersionToKey() throws BuilderException, KeyModifierException {
    // create a key modifier
    KeyModifier keymod = new KeyModifier();

    // create and add a KeyVersion and add it to the Key
    KeyVersion keyversion1 = keymod.addKeyVersion();

    // create and add another KeyVersion and add it to the Key
    KeyVersion keyversion2 = keymod.addKeyVersion();

    // now remove the second KeyVersion from the Key
    keymod.removeKeyVersion(keyversion2);

    // now check that it has in fact been removed
    assertFalse(keymod.containsKeyVersion(keyversion2));
  }

  /**
   * Test that it is not possible to remove the primary key version from the Key
   * @throws BuilderException 
   * @throws KeyModifierException 
   */
  @Test(expected=com.google.k2crypto.exceptions.KeyModifierException.class)
  public void testRemovePrimary() throws BuilderException, KeyModifierException {
    // create a key modifier
    KeyModifier keymod = new KeyModifier();

    // create and add a KeyVersion and add it to the Key
    KeyVersion keyversion = keymod.addKeyVersion();
    
    // now attempt to remove the primary KeyVersion from the Key
    // this SHOULD RAISE AN EXCEPTION
    keymod.removeKeyVersion(keyversion);
  }

  /**
   * Test setting a given KeyVersion as the primary in a Key
   *
   * @throws BuilderException
   */
  @Test
  public void setPrimary() throws BuilderException {
    // create a key modifier
    KeyModifier keymod = new KeyModifier();
    // create and add a KeyVersion and add it to the Key
    KeyVersion keyversion1 = keymod.addKeyVersion();

    // set the first keyversion as the primary
    keymod.setPrimary(keyversion1);
    
    // create and add another KeyVersion and add it to the Key
    KeyVersion keyversion2 = keymod.addKeyVersion();

    // check that the primary key version is equal to the key version we created and added to the
    // Key
    assertEquals(keyversion1, keymod.getPrimary());

    // now update the primary to be the second keyversion
    keymod.setPrimary(keyversion2);

    // check that the Key primary is now the SECOND key version
    assertEquals(keyversion2, keymod.getPrimary());
  }
}
