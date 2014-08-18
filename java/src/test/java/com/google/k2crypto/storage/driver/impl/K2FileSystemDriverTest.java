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

package com.google.k2crypto.storage.driver.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static com.google.k2crypto.storage.driver.impl.K2FileSystemDriver.FILE_EXTENSION;
import static com.google.k2crypto.storage.driver.impl.K2FileSystemDriver.MAX_FILENAME_LENGTH;
import static com.google.k2crypto.storage.driver.impl.K2FileSystemDriver.NATIVE_SCHEME;
import static com.google.k2crypto.storage.driver.impl.K2FileSystemDriver.TEMP_A_EXTENSION;
import static com.google.k2crypto.storage.driver.impl.K2FileSystemDriver.TEMP_B_EXTENSION;
import static com.google.k2crypto.storage.driver.impl.K2FileSystemDriver.TEMP_PREFIX;

import com.google.k2crypto.K2Exception;
import com.google.k2crypto.storage.IllegalAddressException;
import com.google.k2crypto.storage.StoreIOException;
import com.google.k2crypto.storage.driver.Driver;
import com.google.k2crypto.storage.driver.FileBasedDriverTest;

import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URI;

/**
 * Unit tests for the K2 native file-system driver.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class K2FileSystemDriverTest
    extends FileBasedDriverTest<K2FileSystemDriver> {

  // Limit to prevent tests from stalling completely if something goes wrong
  // during random generation of test files 
  private static final int MAX_TRIPLE_GENERATION_ATTEMPTS = 10;

  // File scheme prefix to add to addresses
  private static final String FILE_PREFIX = "file:"; 
  
  // Native scheme prefix to add to addresses 
  private static final String NATIVE_PREFIX = NATIVE_SCHEME + ':';
  
  // Native file extension to add to addresses
  private static final String NATIVE_POSTFIX = '.' + FILE_EXTENSION;
  
  /**
   * Constructs the driver test class.
   */
  public K2FileSystemDriverTest() {
    super(K2FileSystemDriver.class);
  }
  
  /**
   * Tests that the open() method rejects all syntactically invalid
   * URI addresses.
   */
  @Test public final void testRejectBadAddresses() {
    final String testingDirPath = getTestingDirPath();
    
    // Test unsupported components
    checkRejectAddress(
        FILE_PREFIX + "//host/path",
        IllegalAddressException.Reason.AUTHORITY_UNSUPPORTED);
    checkRejectAddress(
        FILE_PREFIX + "//user@localhost:80/path",
        IllegalAddressException.Reason.AUTHORITY_UNSUPPORTED);
    checkRejectAddress(
        FILE_PREFIX + "/path?que",
        IllegalAddressException.Reason.QUERY_UNSUPPORTED);
    checkRejectAddress(
        FILE_PREFIX + "/path#frag",
        IllegalAddressException.Reason.FRAGMENT_UNSUPPORTED);
    
    // Test invalid schemes
    checkRejectAddress(
        "k3:/path",
        IllegalAddressException.Reason.INVALID_SCHEME);
    checkRejectAddress(
        "keyczar:/path",
        IllegalAddressException.Reason.INVALID_SCHEME);
    
    // Test generic schemes without the proper lowercase ".k2k" extension
    checkRejectAddress(
        testingDirPath + "myfile",
        IllegalAddressException.Reason.INVALID_PATH);
    checkRejectAddress(
        testingDirPath + "myfile" + NATIVE_POSTFIX.toUpperCase(),
        IllegalAddressException.Reason.INVALID_PATH);
    checkRejectAddress(
        FILE_PREFIX + testingDirPath + "myfile",
        IllegalAddressException.Reason.INVALID_PATH);
    checkRejectAddress(
        FILE_PREFIX + testingDirPath + "myfile" + NATIVE_POSTFIX.toUpperCase(),
        IllegalAddressException.Reason.INVALID_PATH);
    checkRejectAddress(
        FILE_PREFIX + testingDirPath + "myfile%2e%6B%32%4B",
        IllegalAddressException.Reason.INVALID_PATH);
    
    // Test no path
    checkRejectAddress(
        NATIVE_PREFIX + "?",
        IllegalAddressException.Reason.MISSING_PATH);
    
    // Test relative path going beyond the logical URI root
    checkRejectAddress(
        "/../my%20key",
        IllegalAddressException.Reason.INVALID_PATH);
    
    final String testingAddress = NATIVE_PREFIX + testingDirPath;
    
    // Test all illegal filename characters
    for (char illegal : new char[] {
        '\0', '\n', '\r', '\t', '\f', '\b', '\u007F',
        '\\', '/', '*', '?', '|', '<', '>', ':', ';', '"'
    }) {
      String encoded = String.format("%%%02X", (int)illegal);
      assertEquals(3, encoded.length()); // sanity check
      checkRejectAddress(
          testingAddress + 'A' + encoded + 'Z',
          IllegalAddressException.Reason.INVALID_PATH);
      checkRejectAddress(
          testingAddress + encoded,
          IllegalAddressException.Reason.INVALID_PATH);
    }
    
    // Test illegal filename prefixes
    for (String illegalPrefix : new String[] { "~", ".", "%20" }) {
      checkRejectAddress(
          testingAddress + illegalPrefix + "abc",
          IllegalAddressException.Reason.INVALID_PATH);
    }

    // Test illegal filename postfixes
    for (String illegalPostfix : new String[] { ".", "%20" }) {
      checkRejectAddress(
          testingAddress + "abc" + illegalPostfix,
          IllegalAddressException.Reason.INVALID_PATH);
    }
  }
  
  /**
   * Tests that the open() method accepts a filename at maximum length and
   * rejects when it is any longer.
   */
  @Test public final void testFilenameLength() throws K2Exception {
    final String testingAddress = NATIVE_PREFIX + getTestingDirPath();

    // Test filename that is one character too long
    String oneCharTooLongName = generateString(1 + MAX_FILENAME_LENGTH);
    checkRejectAddress(
        testingAddress + oneCharTooLongName,
        IllegalAddressException.Reason.INVALID_PATH);
    
    // Test acceptance of filename at maximum length
    Driver driver = newDriver();
    try {
      driver.open(URI.create(
          testingAddress + generateString(MAX_FILENAME_LENGTH)));
    } finally {
      driver.close();
    }  
  }
  
  /**
   * Tests that the open() method rejects addresses pointing to a bad 
   * file location (on disk). 
   */
  @Test public final void testRejectBadFileLocation() throws IOException {
    // We can only run this test if there is a physical root available
    File[] roots = File.listRoots();
    if (roots != null) {
      // Should not be able to open the root path (without a filename)
      for (File root : roots) {
        checkRejectAddress(
            NATIVE_PREFIX + root.toURI().getRawPath(),
            IllegalAddressException.Reason.INVALID_PATH);
      }
    }
    
    // The parent "File" of the key file should be an existing directory
    // (and not a file)
    File parent = generateFile(getTestingDir(), "", ".tmp");
    parent.deleteOnExit();
    try {
      assertTrue(parent.createNewFile());
      checkRejectAddress(
          NATIVE_PREFIX + parent.toURI().getRawPath() + "/keys",
          IllegalAddressException.Reason.INVALID_PATH);
    } finally {
      parent.delete();
    }
    
    // Generate the main key file and two temp files for it that do not exist.
    File[] files = generateFileTriple(getTestingDir());
    deleteAllOnExit(files);
    
    // Check that the driver rejects opening the main file address
    // if any of these files is a directory.
    try {
      String mainAddress = NATIVE_PREFIX + files[0].toURI().getRawPath();
      for (File f : files) {
        assertTrue(f.mkdir());
        checkRejectAddress(
            mainAddress, IllegalAddressException.Reason.INVALID_PATH);
        assertTrue(f.delete());
      }
    } finally {
      deleteAll(files);
    }
  }
  
  /**
   * Tests that various addresses are normalized correctly.
   */
  @Test public final void testAddressNormalization() throws K2Exception {
    final String absTestingPath = getTestingDirPath();
    final String absTestingAddress = NATIVE_PREFIX + absTestingPath;
    final String relTestingPath = getRelativeTestingDirPath();
    
    final String filename = generateSafeFilename(getTestingDir());
    final String expected = absTestingAddress + filename;
    
    // Test absolute addresses (with k2: scheme), without and with extension
    checkNormalization(expected, absTestingAddress + filename);
    checkNormalization(expected, absTestingAddress + filename + NATIVE_POSTFIX);

    // Test with empty query and fragment
    checkNormalization(expected, absTestingAddress + filename + '?');
    checkNormalization(expected, absTestingAddress + filename + '#');

    // Test absolute addresses with collapsable paths, w/o and w/ extension
    checkNormalization(expected,
        absTestingAddress + "anything/./something/.././../" + filename);
    checkNormalization(expected,
        absTestingAddress + "/././" + filename + NATIVE_POSTFIX);
    
    // Test the above with absolute paths (i.e. no k2: scheme) 
    checkNormalization(expected, absTestingPath + filename + NATIVE_POSTFIX);
    checkNormalization(expected,
        absTestingPath + "/./something/../" + filename + NATIVE_POSTFIX);
    
    // Test the above with relative paths
    checkNormalization(expected, relTestingPath + filename + NATIVE_POSTFIX);
    checkNormalization(expected,
        relTestingPath + "/anything/../" + filename + NATIVE_POSTFIX);
  }
  
  /**
   * Tests saving, loading and erasing keys. 
   */
  @Test public final void testSaveLoadErase() throws K2Exception {
    File[] files = generateFileTriple(getTestingDir());
    URI address = files[0].toURI().normalize();
    deleteAllOnExit(files);
    
    K2FileSystemDriver driver = newDriver();
    try {
      driver.open(address);
      checkLoadSaveErase(driver);
    } finally {
      deleteAll(files);
      driver.close();
    }
  }
  
  /**
   * Tests recovering a key from any save slot. 
   */
  @Test public final void testRecovery() throws K2Exception, IOException {
    File[] files = generateFileTriple(getTestingDir());
    URI address = files[0].toURI().normalize();
    deleteAllOnExit(files);
    
    K2FileSystemDriver driver = newDriver();
    try {
      // Open and save a key
      assertEquals(
          NATIVE_PREFIX + address.getSchemeSpecificPart(),
          driver.open(address) + NATIVE_POSTFIX);
      driver.save(EMPTY_KEY);
      
      // Verify that we can load when key data is in any slot
      File last = null;
      for (File current : files) {
        if (last != null) {
          // Move data to next slot
          assertTrue(last.renameTo(current));
          assertFalse(last.exists());
        }
        
        // Check that the slot is readable
        assertTrue(current.isFile());
        checkLoad(driver, EMPTY_KEY);

        // Check it is still readable with corrupted (empty)
        // files in some other slot
        for (File f : files) {
          if (f != current) {
            assertFalse(f.exists());            
            assertTrue(f.createNewFile());
            checkLoad(driver, EMPTY_KEY);
            assertTrue(f.delete());
          }
        }        
        last = current;
      }
      
    } finally {
      deleteAll(files);
      driver.close();
    }
  }
  
  /**
   * Tests precedence of recovery when there is more than one readable slot. 
   */
  @Test public final void testRecoveryPrecedence()
      throws K2Exception, IOException {
    final File keyFile =
        generateFile(getTestingDir(), "key", NATIVE_POSTFIX);
    final File emptyFile =
        generateFile(getTestingDir(), "empty", NATIVE_POSTFIX);
    File[] files = generateFileTriple(getTestingDir());
    URI address = files[0].toURI().normalize();
    
    keyFile.deleteOnExit();
    emptyFile.deleteOnExit();
    deleteAllOnExit(files);

    K2FileSystemDriver driver = newDriver();
    try {
      // Open store and perform some initial setup
      assertEquals(
          NATIVE_PREFIX + address.getSchemeSpecificPart(),
          driver.open(address) + NATIVE_POSTFIX);
      
      // Save then put aside the two keys as test data
      driver.save(MOCK_KEY);
      assertTrue(files[0].renameTo(keyFile));
      assertTrue(driver.isEmpty());
      driver.save(EMPTY_KEY);
      assertTrue(files[0].renameTo(emptyFile));
      assertTrue(driver.isEmpty());

      // If both temp files are readable, the later one takes precedence 
      copyData(keyFile, files[1]);
      files[1].setLastModified(Math.max(files[1].lastModified() - 5000, 0));
      copyData(emptyFile, files[2]);
      checkLoad(driver, EMPTY_KEY);
      
      // If both have the same timestamp, the larger one takes precedence
      files[1].setLastModified(files[2].lastModified());
      checkLoad(driver, MOCK_KEY);
      
      // If main file exists, it always takes precedence
      copyData(emptyFile, files[0]);
      checkLoad(driver, EMPTY_KEY);
      
      // If the main file is corrupted, we fallback to the temporary files
      files[0].delete();
      files[0].createNewFile();
      checkLoad(driver, MOCK_KEY);
      
    } finally {
      deleteAll(files);
      keyFile.delete();
      emptyFile.delete();
      driver.close();
    }
  }
  
  /**
   * Tests loading and erasing of corrupted files.
   */
  @Test public final void testLoadEraseCorrupted()
      throws K2Exception, IOException {
    File[] files = generateFileTriple(getTestingDir());
    URI address = files[0].toURI().normalize();
    deleteAllOnExit(files);
    
    K2FileSystemDriver driver = newDriver();
    try {
      // Open the driver
      assertEquals(
          NATIVE_PREFIX + address.getSchemeSpecificPart(),
          driver.open(address) + NATIVE_POSTFIX);

      // Check that loading fails with empty files in each slot
      for (File f : files) {
        assertFalse(f.exists());
        assertTrue(f.createNewFile());
        checkLoadFails(driver, StoreIOException.Reason.DESERIALIZATION_ERROR);
        assertTrue(driver.erase());
        assertTrue(driver.isEmpty());
      }

      // Check that loading fails when all slots have empty files
      for (File f : files) {
        assertFalse(f.exists());
        assertTrue(f.createNewFile());
      }
      checkLoadFails(driver, StoreIOException.Reason.DESERIALIZATION_ERROR);
      
      // Make sure that an erase wipes all the slots
      assertTrue(driver.erase());
      assertTrue(driver.isEmpty());
      for (File f : files) {
        assertFalse(f.exists());
      }      
      
    } finally {
      deleteAll(files);
      driver.close();
    }
  }

  /**
   * Generates a path to a K2 key location that does not currently exist. 
   * 
   * @param dir Directory that the key should be in.
   * 
   * @return path to the K2 key file without the extension. 
   */
  private String generateSafeFilename(File dir) {
    String name = generateFileTriple(dir)[0].getName();
    return name.substring(0, name.length() - NATIVE_POSTFIX.length());
  }
  
  /**
   * Generates a new K2 key location and returns the three (currently
   * non-existent) files that the driver will use for storing a key in it. 
   * The first file in the returned array will be the main key file, while 
   * the remaining two will be the temporary/backup files. 
   * 
   * @param dir Directory that the key should be in.
   * 
   * @return a 3-element array with the main key file at index 0 and the 
   *         temporary/backup files in the remaining slots. 
   */
  private File[] generateFileTriple(File dir) {
    // Generate the main key file and two temp files for it that do not exist.
    File[] files = new File[3];
    int countdown = MAX_TRIPLE_GENERATION_ATTEMPTS;
    do {
      if (--countdown < 0) {
        fail("Could not generate file triple!");
      }
      // Main file
      File main = files[0] = generateFile(dir, "", NATIVE_POSTFIX);
      // Temp files
      files[1] = new File(dir, TEMP_PREFIX + main.getName() + TEMP_A_EXTENSION);
      files[2] = new File(dir, TEMP_PREFIX + main.getName() + TEMP_B_EXTENSION);      
    } while (files[1].exists() || files[2].exists());
    return files;
  }
}
