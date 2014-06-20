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

import java.util.ArrayList;

/**
 * This class represents a Key in K2. It holds a list of KeyVersions and a reference to the primary
 * KeyVersion.
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class Key {
  // The list of key versions
  // Andrew prefers to use ArrayList instead of LinkedList
  ArrayList<KeyVersion> keyVersions = new ArrayList<KeyVersion>();
  KeyVersion primary;

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
}
