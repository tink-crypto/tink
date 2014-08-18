/*
 * Copyright 2014 Google. Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.k2crypto.examples;

import com.google.k2crypto.K2Context;
import com.google.k2crypto.K2Exception;
import com.google.k2crypto.Key;
import com.google.k2crypto.exceptions.BuilderException;
import com.google.k2crypto.exceptions.KeyVersionException;
import com.google.k2crypto.keyversions.AESKeyVersion;
import com.google.k2crypto.keyversions.HMACKeyVersion;
import com.google.k2crypto.keyversions.KeyVersionRegistry;
import com.google.k2crypto.storage.K2Storage;
import com.google.k2crypto.storage.StorageDriverException;
import com.google.k2crypto.storage.Store;
import com.google.k2crypto.storage.driver.impl.K2FileSystemDriver;
import com.google.k2crypto.storage.driver.impl.K2MemoryDriver;
import com.google.k2crypto.storage.driver.optional.SqliteDriver;

import java.io.File;

/**
 * Example for how to use the storage system.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public final class StorageExample {

  // Directory for the example code to save and load keys
  private static final File WORKING_DIRECTORY =
      new File("./build/tmp/");
  
  // File pointing to a native K2 key file
  private static final File NATIVE_STORE =
      new File(WORKING_DIRECTORY, "example mykeys.k2k");
  
  // File pointing to a SQLite database file
  private static final File SQLITE_DATABASE =
      new File(WORKING_DIRECTORY, "example sqlite.db");
  
  /**
   * Main method executing the example.
   */
  public static void main(String[] args) throws K2Exception {
    // Create working directory and wipe example files
    WORKING_DIRECTORY.mkdirs();
    assert(WORKING_DIRECTORY.isDirectory());
    NATIVE_STORE.delete();
    SQLITE_DATABASE.delete();
    NATIVE_STORE.deleteOnExit();
    SQLITE_DATABASE.deleteOnExit();

    // Initialize context and storage system
    K2Context context = new K2Context();
    K2Storage storage = new K2Storage(context);
    
    // Register available key versions
    KeyVersionRegistry registry = context.getKeyVersionRegistry();
    try {
      registry.register(AESKeyVersion.class);
      registry.register(HMACKeyVersion.class);
    } catch (KeyVersionException ex) {
      // Something wrong with a key version
      throw ex;
    }
    
    // Install desired storage drivers in order of preference
    try {
      storage.installDriver(K2FileSystemDriver.class);
      storage.installDriver(SqliteDriver.class);
      storage.installDriver(K2MemoryDriver.class);
    } catch (StorageDriverException ex) {
      // Something wrong with a storage driver
      throw ex;
    }
    
    // Create a key
    Key original;
    try {
      original = new Key(new AESKeyVersion.Builder().build());
    } catch (BuilderException ex) {
      // Problem building key
      throw ex;
    }
    
    // Quickly save it (the native driver recognizes file:// addresses)
    storage.save(NATIVE_STORE.toURI(), original);
    
    // Quickly load it back
    Key loaded = storage.load(NATIVE_STORE.toURI());
    assert(original.buildData().build().equals(loaded.buildData().build()));
    
    // Use Store API for more elaborate operations
    Store store = null;
    try {
      // Open a SQLite database store
      store = storage.open(
          "sqlite:" + SQLITE_DATABASE.toURI().getRawPath() + "#samekey");
      
      // Save previously loaded key 
      store.save(loaded);
      
      // Check store is not empty and load key back 
      if (!store.isEmpty()) {
        Key sameKey = store.load();
        assert(loaded.buildData().build().equals(sameKey.buildData().build()));
      }
      
    } finally {
      // Close store
      if (store != null) {
        store.close();
      }
    }
  }
}
