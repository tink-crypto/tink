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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static com.google.k2crypto.storage.driver.impl.K2FileSystemDriver.FILE_EXTENSION;
import static com.google.k2crypto.storage.driver.impl.K2FileSystemDriver.MAX_FILENAME_LENGTH;
import static com.google.k2crypto.storage.driver.impl.K2FileSystemDriver.NATIVE_SCHEME;
import static com.google.k2crypto.storage.driver.impl.K2FileSystemDriver.TEMP_A_EXTENSION;
import static com.google.k2crypto.storage.driver.impl.K2FileSystemDriver.TEMP_B_EXTENSION;
import static com.google.k2crypto.storage.driver.impl.K2FileSystemDriver.TEMP_PREFIX;

import com.google.k2crypto.K2Context;
import com.google.k2crypto.K2Exception;
import com.google.k2crypto.Key;
import com.google.k2crypto.keyversions.MockKeyVersion;
import com.google.k2crypto.storage.IllegalAddressException;
import com.google.k2crypto.storage.K2Storage;
import com.google.k2crypto.storage.StorageDriverException;
import com.google.k2crypto.storage.StoreException;
import com.google.k2crypto.storage.StoreIOException;
import com.google.k2crypto.storage.driver.Driver;
import com.google.k2crypto.storage.driver.ReadableDriver;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.channels.FileChannel;
import java.util.Random;

/**
 * Unit tests for the K2 native file-system driver.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@RunWith(JUnit4.class)
public class K2FileSystemDriverTest {

  // Directory for the driver to read/write test key files
  private static final String TESTING_DIRECTORY = "./build/tmp/"; 
  
  // Native scheme prefix to add to addresses 
  private static final String NATIVE_PREFIX = NATIVE_SCHEME + ':';
  
  // Native file extension to add to addresses
  private static final String NATIVE_POSTFIX = '.' + FILE_EXTENSION;
  
  // File scheme prefix to add to addresses
  private static final String FILE_PREFIX = "file:"; 
  
  // Limit to prevent tests from stalling completely if something goes wrong
  // during random generation of test files 
  private static final int MAX_GENERATION_ATTEMPTS = 100;
 
  // Length of the randomly generated portion of filenames
  private static final int GENERATED_NAME_LENGTH = 64;
  
  private K2Context context = null;
  
  private Key emptyKey = null;
  
  private Key mockKey = null;

  private Random random = null;
  
  private File testingDir = null;
  
  private String testingDirPath = null;

  /**
   * Creates a context, test keys and initializes the working directory.
   */
  @Before public final void setUp() throws K2Exception {
    context = new K2Context();
    context.getKeyVersionRegistry().register(MockKeyVersion.class);
    
    emptyKey = new Key();
    mockKey =
        new Key(new MockKeyVersion.Builder().comments("testing key").build());
    
    random = new Random(); // for generating test files
    
    testingDir = new File(TESTING_DIRECTORY);
    testingDir.mkdirs();
    if (!testingDir.isDirectory() || !testingDir.canWrite()) {
      throw new IllegalStateException("Could not access test directory.");
    }
    testingDirPath = testingDir.toURI().normalize().getRawPath();
    if (!testingDirPath.endsWith("/")) {
      testingDirPath += "/";
    }
  }

  /**
   * Creates an initialized instance of the K2 driver for a test.
   */
  private K2FileSystemDriver newDriver() {
    K2FileSystemDriver driver = new K2FileSystemDriver();
    driver.initialize(context);
    return driver;
  }
  
  /**
   * Test that the driver has a valid structure by attempting to install it.
   */
  @Test public final void testDriverStructure() {
    K2Storage storage = new K2Storage(context);
    try {
      storage.installDriver(K2FileSystemDriver.class);
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
    final String testingAddress = NATIVE_PREFIX + testingDirPath;

    // Test filename that is one character too long
    String oneCharTooLongName = generateString(random, 1 + MAX_FILENAME_LENGTH);
    checkRejectAddress(
        testingAddress + oneCharTooLongName,
        IllegalAddressException.Reason.INVALID_PATH);
    
    // Test acceptance of filename at maximum length
    Driver driver = newDriver();
    try {
      driver.open(URI.create(
          testingAddress + generateString(random, MAX_FILENAME_LENGTH)));
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
    File parent = generateFile(random, testingDir, "", ".tmp");
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
    File[] files = generateFileTriple(random, testingDir);
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
   * Checks that the address is rejected by the driver for the given reason.
   * 
   * @param address Address to open.
   * @param reason Reason the address is rejected.
   */
  private void checkRejectAddress(
      String address, IllegalAddressException.Reason reason) {
    Driver driver = newDriver();
    try {
      driver.open(URI.create(address));
      fail("Should reject " + address);
    } catch (StoreException ex) {
      throw new AssertionError("Unexpected", ex);
    } catch (IllegalAddressException expected) {
      assertEquals(reason, expected.getReason());
      assertEquals(address, expected.getAddress());
    } finally {
      driver.close();
    }
  }
  
  /**
   * Tests that various addresses are normalized correctly.
   */
  @Test public final void testAddressNormalization() throws K2Exception {
    final String absTestingAddress = NATIVE_PREFIX + testingDirPath;
    final String absTestingPath = testingDirPath;
    final String relTestingPath = TESTING_DIRECTORY;
    
    final String filename = generateSafeFilename(random, testingDir);
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
    File[] files = generateFileTriple(random, testingDir);
    URI address = files[0].toURI().normalize();
    deleteAllOnExit(files);
    
    K2FileSystemDriver driver = newDriver();
    try {
      assertEquals(
          NATIVE_PREFIX + address.getSchemeSpecificPart(),
          driver.open(address) + NATIVE_POSTFIX);
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
      deleteAll(files);
      driver.close();
    }
  }
  
  /**
   * Tests recovering a key from any save slot. 
   */
  @Test public final void testRecovery() throws K2Exception, IOException {
    File[] files = generateFileTriple(random, testingDir);
    URI address = files[0].toURI().normalize();
    deleteAllOnExit(files);
    
    K2FileSystemDriver driver = newDriver();
    try {
      // Open and save a key
      assertEquals(
          NATIVE_PREFIX + address.getSchemeSpecificPart(),
          driver.open(address) + NATIVE_POSTFIX);
      driver.save(emptyKey);
      
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
        loadAndCheck(driver, emptyKey);

        // Check it is still readable with corrupted (empty)
        // files in some other slot
        for (File f : files) {
          if (f != current) {
            assertFalse(f.exists());            
            assertTrue(f.createNewFile());
            loadAndCheck(driver, emptyKey);
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
        generateFile(random, testingDir, "key", NATIVE_POSTFIX);
    final File emptyFile =
        generateFile(random, testingDir, "empty", NATIVE_POSTFIX);
    File[] files = generateFileTriple(random, testingDir);
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
      driver.save(mockKey);
      assertTrue(files[0].renameTo(keyFile));
      assertTrue(driver.isEmpty());
      driver.save(emptyKey);
      assertTrue(files[0].renameTo(emptyFile));
      assertTrue(driver.isEmpty());

      // If both temp files are readable, the later one takes precedence 
      copyData(keyFile, files[1]);
      files[1].setLastModified(Math.max(files[1].lastModified() - 5000, 0));
      copyData(emptyFile, files[2]);
      loadAndCheck(driver, emptyKey);
      
      // If both have the same timestamp, the larger one takes precedence
      files[1].setLastModified(files[2].lastModified());
      loadAndCheck(driver, mockKey);
      
      // If main file exists, it always takes precedence
      copyData(emptyFile, files[0]);
      loadAndCheck(driver, emptyKey);
      
      // If the main file is corrupted, we fallback to the temporary files
      files[0].delete();
      files[0].createNewFile();
      loadAndCheck(driver, mockKey);
      
    } finally {
      deleteAll(files);
      keyFile.delete();
      emptyFile.delete();
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
   * Tests loading and erasing of corrupted files.
   */
  @Test public final void testLoadEraseCorrupted()
      throws K2Exception, IOException {
    File[] files = generateFileTriple(random, testingDir);
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
        checkLoadFails(driver);
        assertTrue(driver.erase());
        assertTrue(driver.isEmpty());
      }

      // Check that loading fails when all slots have empty files
      for (File f : files) {
        assertFalse(f.exists());
        assertTrue(f.createNewFile());
      }
      checkLoadFails(driver);
      
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
   * Checks that a load fails on the driver because of corrupted data.
   * 
   * @param driver Driver to load from.
   * 
   * @throws StoreException if there is an unexpected error.
   */
  private static void checkLoadFails(K2FileSystemDriver driver)
      throws StoreException {
    assertFalse(driver.isEmpty());
    try {    
      driver.load();
      fail("Load should fail.");
    } catch (StoreIOException expected) {
      assertEquals(
          StoreIOException.Reason.DESERIALIZATION_ERROR,
          expected.getReason());
    }
  }
  
  /**
   * Copies a file. 
   * 
   * @param source File to copy.
   * @param destination The copy to create.
   */
  private static void copyData(File source, File destination) {
    FileChannel in = null;
    FileChannel out = null;
    try {
      in = new FileInputStream(source).getChannel();
      out = new FileOutputStream(destination).getChannel();
      out.transferFrom(in, 0, in.size());
    } catch (IOException ex) {
      throw new AssertionError("Could not copy file", ex);
    } finally {
      try { in.close(); }
      catch (Exception ex) {}
      try { out.close(); }
      catch (Exception ex) {}
    }
  }
  
  /**
   * Marks the given files for deletion on VM exit.  
   * 
   * @param files Files to delete.
   */
  private static void deleteAllOnExit(File ... files) {
    for (File f : files) {
      f.deleteOnExit();
    }
  }
  
  /**
   * Deletes the given files immediately.  
   * 
   * @param files Files to delete.
   */
  private static void deleteAll(File ... files) {
    for (File f : files) {
      f.delete();
    }
  }

  /**
   * Generates a path to a K2 key location that does not currently exist. 
   * 
   * @param random Random source.
   * @param dir Directory that the key should be in.
   * 
   * @return path to the K2 key file without the extension. 
   */
  private static String generateSafeFilename(Random random, File dir) {
    String name = generateFileTriple(random, dir)[0].getName();
    return name.substring(0, name.length() - NATIVE_POSTFIX.length());
  }
  
  /**
   * Generates a new K2 key location and returns the three (currently
   * non-existent) files that the driver will use for storing a key in it. 
   * The first file in the returned array will be the main key file, while 
   * the remaining two will be the temporary/backup files. 
   * 
   * @param random Random source.
   * @param dir Directory that the key should be in.
   * 
   * @return a 3-element array with the main key file at index 0 and the 
   *         temporary/backup files in the remaining slots. 
   */
  private static File[] generateFileTriple(Random random, File dir) {
    // Generate the main key file and two temp files for it that do not exist.
    File[] files = new File[3];
    int countdown = MAX_GENERATION_ATTEMPTS;
    do {
      if (--countdown < 0) {
        fail("Could not generate file triple!");
      }
      // Main file
      File main = files[0] = generateFile(random, dir, "", NATIVE_POSTFIX);
      // Temp files
      files[1] = new File(dir, TEMP_PREFIX + main.getName() + TEMP_A_EXTENSION);
      files[2] = new File(dir, TEMP_PREFIX + main.getName() + TEMP_B_EXTENSION);      
    } while (files[1].exists() || files[2].exists());
    return files;
  }
  
  /**
   * Generates a file that does not currently exist.
   * 
   * @param random Random source.
   * @param dir Directory that the file should be in.
   * @param prefix String to append at the start of the generated filename.
   * @param postfix String to append at the end of the generated filename.
   * 
   * @return a non-existent file in the given directory.
   */
  private static File generateFile(
      Random random, File dir, String prefix, String postfix) {
    final int prefixLen = prefix.length();
    final int postfixLen = postfix.length();
    
    // Create an initial random filename
    char[] filename = new char[prefixLen + GENERATED_NAME_LENGTH + postfixLen];
    prefix.getChars(0, prefixLen, filename, 0);
    postfix.getChars(
        0, postfixLen, filename, GENERATED_NAME_LENGTH + prefixLen);
    
    for (int i = GENERATED_NAME_LENGTH + prefixLen; --i >= prefixLen; ) {
      filename[i] = (char)('A' + random.nextInt(26));
    }
    
    // Mutate one character each time until we get a non-existent file 
    File file;
    int countdown = MAX_GENERATION_ATTEMPTS;
    while ((file = new File(dir, new String(filename))).exists()) {
      filename[prefixLen + random.nextInt(GENERATED_NAME_LENGTH)] =
          (char)('a' + random.nextInt(26));
      if (--countdown <= 0) {
        fail("Could not generate file!");
      }
    }
    return file;
  }
  
  /**
   * Generates a random string of digits.
   * 
   * @param random Random source.
   * @param length Length of the string to generate.
   * 
   * @return the generated string.
   */
  private static String generateString(Random random, int length) {
    char[] buffer = new char[length];
    for (int i = buffer.length; --i >= 0; ) {
      buffer[i] = (char)('0' + random.nextInt(10)); 
    }
    return new String(buffer);
  }
}
