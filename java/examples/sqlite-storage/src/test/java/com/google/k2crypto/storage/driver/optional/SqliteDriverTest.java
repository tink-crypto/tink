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

package com.google.k2crypto.storage.driver.optional;

import static com.google.k2crypto.storage.driver.optional.SqliteDriver.MAX_KEY_ID_LENGTH;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.k2crypto.K2Exception;
import com.google.k2crypto.Key;
import com.google.k2crypto.K2Context;
import com.google.k2crypto.keyversions.MockKeyVersion;
import com.google.k2crypto.storage.IllegalAddressException;
import com.google.k2crypto.storage.K2Storage;
import com.google.k2crypto.storage.StorageDriverException;
import com.google.k2crypto.storage.StoreException;
import com.google.k2crypto.storage.driver.Driver;
import com.google.k2crypto.storage.driver.ReadableDriver;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.File;
import java.io.IOException;
import java.net.URI;

/**
 * Unit tests for the SQLite storage driver.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@RunWith(JUnit4.class)
public class SqliteDriverTest {

  // Directory for the driver to read/write test key files
  private static final File TESTING_DIRECTORY = new File("./build/tmp/"); 

  // Scheme prefix to add to addresses 
  private static final String ADDRESS_PREFIX = SqliteDriver.SCHEME + ':';
  
  // Generic key id postfix to add to addresses 
  private static final String GENERIC_KEY_ID = "#key"; 

  private K2Context context = null;

  private Key emptyKey = null;
  
  private Key mockKey = null;

  /**
   * Creates a context, test keys and verifies the testing directory.
   */
  @Before public final void setUp() throws K2Exception {
    context = new K2Context();
    context.getKeyVersionRegistry().register(MockKeyVersion.class);
    
    emptyKey = new Key();
    mockKey =
        new Key(new MockKeyVersion.Builder().comments("testing key").build());
    
    File dir = TESTING_DIRECTORY;
    dir.mkdirs();
    if (!dir.isDirectory() || !dir.canWrite()) {
      throw new IllegalStateException("Could not access test directory.");
    }
  }

  /**
   * Creates an initialized instance of the SQLite driver for a test.
   */
  private SqliteDriver newDriver() {
    SqliteDriver driver = new SqliteDriver();
    driver.initialize(context);
    return driver;
  }
  
  /**
   * Test that the driver has a valid structure by attempting to install it.
   */
  @Test public final void testDriverStructure() {
    K2Storage storage = new K2Storage(context);
    try {
      storage.installDriver(SqliteDriver.class);
    } catch (StorageDriverException ex) {
      throw new AssertionError("Driver structure is bad.", ex);
    }
  }
  
  /**
   * Tests that the open() method rejects all syntactically invalid
   * URI addresses.
   */
  @Test public final void testRejectBadAddresses() {
    // Test unsupported components
    checkRejectAddress(
        ADDRESS_PREFIX + "//host/database" + GENERIC_KEY_ID,
        IllegalAddressException.Reason.AUTHORITY_UNSUPPORTED);
    checkRejectAddress(
        ADDRESS_PREFIX + "//user@localhost:80/database" + GENERIC_KEY_ID,
        IllegalAddressException.Reason.AUTHORITY_UNSUPPORTED);
    checkRejectAddress(
        ADDRESS_PREFIX + "/database?password=1234" + GENERIC_KEY_ID,
        IllegalAddressException.Reason.QUERY_UNSUPPORTED);
    
    // Test invalid schemes
    checkRejectAddress(
        "k2:/database" + GENERIC_KEY_ID,
        IllegalAddressException.Reason.INVALID_SCHEME);
    checkRejectAddress(
        "file:/database" + GENERIC_KEY_ID,
        IllegalAddressException.Reason.INVALID_SCHEME);
    checkRejectAddress(
        "/database" + GENERIC_KEY_ID,
        IllegalAddressException.Reason.INVALID_SCHEME);
    
    // Test no database path
    checkRejectAddress(
        ADDRESS_PREFIX + "host" + GENERIC_KEY_ID,
        IllegalAddressException.Reason.MISSING_PATH);
    
    final String testingAddress =
        ADDRESS_PREFIX + TESTING_DIRECTORY.toURI().getRawPath() + '/';
    
    // Test common illegal database filename characters
    for (char illegal : new char[] {
        '\0', '\n', '\r', '\t', '\f', '\b', '\u007F',
        '\\', '/', '*', '?', '|', '<', '>', ':', ';', '"'
    }) {
      String encoded = String.format("%%%02X", (int)illegal);
      assertEquals(3, encoded.length()); // sanity check
      checkRejectAddress(
          testingAddress + 'A' + encoded + 'Z' + GENERIC_KEY_ID,
          IllegalAddressException.Reason.INVALID_PATH);
      checkRejectAddress(
          testingAddress + encoded + GENERIC_KEY_ID,
          IllegalAddressException.Reason.INVALID_PATH);
    }
    
    // Test illegal database filename prefixes
    for (String illegalPrefix : new String[] { "~", ".", "%20" }) {
      checkRejectAddress(
          testingAddress + illegalPrefix + "abc" + GENERIC_KEY_ID,
          IllegalAddressException.Reason.INVALID_PATH);
    }

    // Test illegal database filename postfixes
    for (String illegalPostfix : new String[] { ".", "%20" }) {
      checkRejectAddress(
          testingAddress + "abc" + illegalPostfix + GENERIC_KEY_ID,
          IllegalAddressException.Reason.INVALID_PATH);
    }
    
    // Test no fragment (key identifier)
    checkRejectAddress(
        ADDRESS_PREFIX + "/database",
        IllegalAddressException.Reason.MISSING_FRAGMENT);

    File db = generateTempDatabase();
    try {
      // Test common illegal key identifier characters
      for (char illegal : new char[] {
          '\0', '\n', '\r', '\t', '\f', '\b', '\u007F', ';'
      }) {
        String encoded = String.format("%%%02X", (int)illegal);
        assertEquals(3, encoded.length()); // sanity check
        checkRejectAddress(
            generateAddress(db, 'A' + encoded + 'Z'),
            IllegalAddressException.Reason.INVALID_FRAGMENT);
        checkRejectAddress(
            generateAddress(db, encoded),
            IllegalAddressException.Reason.INVALID_FRAGMENT);
      }
      
      // Test no spaces at start/end of key identifier
      checkRejectAddress(
          generateAddress(db, "%20key"),
          IllegalAddressException.Reason.INVALID_FRAGMENT);
      checkRejectAddress(
          generateAddress(db, "key%20"),
          IllegalAddressException.Reason.INVALID_FRAGMENT);
    } finally {
      db.delete();
    }
  }
  
  /**
   * Tests that the open() method accepts a key identifier at maximum length
   * and rejects when it is any longer.
   */
  @Test public final void testKeyIdentifierLength() throws K2Exception {
    File db = generateTempDatabase();
    try {
      // Test key identifier that is one character too long
      String oneCharTooLongId =
          String.format("%0" + (MAX_KEY_ID_LENGTH + 1) + "d", 0);
      checkRejectAddress(
          generateAddress(db, oneCharTooLongId),
          IllegalAddressException.Reason.INVALID_FRAGMENT);

      // Test acceptance of identifier at maximum length
      Driver driver = newDriver();
      try {
        driver.open(generateAddress(
            db, String.format("%0" + MAX_KEY_ID_LENGTH + "d", 0)));
      } finally {
        driver.close();
      }  
    } finally {
      db.delete();
    }
  }
  
  /**
   * Tests that the open() method rejects addresses pointing to a bad 
   * database file location (on disk). 
   */
  @Test public final void testRejectBadDatabaseLocation() {
    // We can only run this test if there is a physical root available
    File[] roots = File.listRoots();
    if (roots != null) {
      // Should not be able to open the root path (without a filename)
      for (File root : roots) {
        checkRejectAddress(
            ADDRESS_PREFIX + root.toURI().getRawPath() + GENERIC_KEY_ID,
            IllegalAddressException.Reason.INVALID_PATH);
      }
    }
    
    // The database file should not be a directory.
    File db = generateTempDatabase();
    try {
      assertTrue(db.delete());
      assertTrue(db.mkdir());
      checkRejectAddress(
          ADDRESS_PREFIX + db.toURI().getRawPath() + GENERIC_KEY_ID,
          IllegalAddressException.Reason.INVALID_PATH);
    } finally {
      db.delete();
    }

    // The parent "File" of the database file should be an existing directory
    // (and not a file)
    File parent = generateTempDatabase();
    try {
      checkRejectAddress(
          ADDRESS_PREFIX + parent.toURI().getRawPath() + "/k" + GENERIC_KEY_ID,
          IllegalAddressException.Reason.INVALID_PATH);
    } finally {
      parent.delete();
    }
  }

  /**
   * Checks that the address is rejected by the driver for the given reason.
   * 
   * @param address String address to open.
   * @param reason Reason the address is rejected.
   */
  private void checkRejectAddress(
      String address, IllegalAddressException.Reason reason) {
    checkRejectAddress(URI.create(address), reason);
  }
  
  /**
   * Checks that the address is rejected by the driver for the given reason.
   * 
   * @param address URI address to open.
   * @param reason Reason the address is rejected.
   */
  private void checkRejectAddress(
      URI address, IllegalAddressException.Reason reason) {
    Driver driver = newDriver();
    try {
      driver.open(address);
      fail("Should reject " + address);
    } catch (StoreException ex) {
      throw new AssertionError("Unexpected", ex);
    } catch (IllegalAddressException expected) {
      assertEquals(reason, expected.getReason());
      assertEquals(address.toString(), expected.getAddress());
    } finally {
      driver.close();
    }
  }
  
  /**
   * Tests that various addresses are normalized correctly.
   */
  @Test public final void testAddressNormalization() throws K2Exception {
    File db = generateTempDatabase();
    try {
      final String expected = generateAddress(db, "key").toString();
      
      final String filename = db.getName();
      final String absTestingPath = new File("").toURI()
          .resolve(db.getParentFile().toURI().getRawPath())
          .normalize().getRawPath();
      final String absTestingAddress = ADDRESS_PREFIX + absTestingPath;
      
      checkNormalization(expected,
          absTestingAddress + filename + GENERIC_KEY_ID);
      checkNormalization(expected,
          absTestingAddress + filename + '?' + GENERIC_KEY_ID);
      checkNormalization(expected,
          absTestingAddress + "/././" + filename + GENERIC_KEY_ID);
      checkNormalization(expected,
          absTestingAddress + "a/./b/.././../" + filename + GENERIC_KEY_ID);
      
    } finally {
      db.delete();
    }
  }
  
  /**
   * Checks that the address is normalized correctly. 
   * 
   * @param expected Expected result of normalization.
   * @param address Address to check.
   * 
   * @throws K2Exception if there is an unexpected failure opening the address.
   */
  private void checkNormalization(String expected, String address)
      throws K2Exception {
    Driver driver = newDriver();
    try {
      URI result = driver.open(URI.create(address));
      assertEquals(expected, result.toString());
    } finally {
      driver.close();
    }
  }
  
  /**
   * Tests saving, loading and erasing keys. 
   */
  @Test public final void testSaveLoadErase() throws K2Exception {
    File db = generateTempDatabase();
    SqliteDriver driver = newDriver();
    try {
      driver.open(generateAddress(db, "my%20key"));
      assertFalse(driver.erase());
      assertTrue(driver.isEmpty());
      assertNull(driver.load());

      driver.save(mockKey);
      assertFalse(driver.isEmpty());
      loadAndCheck(driver, mockKey);
      
      driver.save(emptyKey);
      assertFalse(driver.isEmpty());
      loadAndCheck(driver, emptyKey);

      assertTrue(driver.erase());
      assertTrue(driver.isEmpty());
      assertNull(driver.load());
      assertFalse(driver.erase());
      
    } finally {
      db.delete();
      driver.close();
    }
  }

  /**
   * Checks that the driver loads the given key. 
   * 
   * @param driver Driver to load from.
   * @param expected The key that should be loaded.
   * 
   * @throws StoreException if there is an unexpected error loading. 
   */
  private static void loadAndCheck(ReadableDriver driver, Key expected)
      throws StoreException {
    assertFalse(driver.isEmpty());
    Key loaded = driver.load();
    assertEquals(
        expected.buildData().build().toByteString(),
        loaded.buildData().build().toByteString());    
  }

  /**
   * Generates an empty temporary database file for testing. 
   */
  private static File generateTempDatabase() {
    try {
      File db = File.createTempFile("sqlite", ".db", TESTING_DIRECTORY);
      db.deleteOnExit();
      return db;
    } catch (IOException ex) {
      throw new AssertionError("Could not create database.", ex);
    }
  }
  
  /**
   * Generates a storage address that points to the given database file and key.
   * 
   * @param database File of the database (on disk).
   * @param keyName Raw name of the key (appended as the URI fragment).
   * 
   * @return a URI address pointing to the given database and key. 
   */
  private static URI generateAddress(File database, String keyName) {
    return URI.create(ADDRESS_PREFIX + database.toURI().normalize().getRawPath()
        + '#' + keyName);
  }  
}
