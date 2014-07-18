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

package com.google.k2crypto.storage.drivers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static com.google.k2crypto.storage.drivers.K2FileSystemDriver.NATIVE_SCHEME;
import static com.google.k2crypto.storage.drivers.K2FileSystemDriver.FILE_EXTENSION;
import static com.google.k2crypto.storage.drivers.K2FileSystemDriver.TEMP_A_EXTENSION;
import static com.google.k2crypto.storage.drivers.K2FileSystemDriver.TEMP_B_EXTENSION;
import static com.google.k2crypto.storage.drivers.K2FileSystemDriver.TEMP_PREFIX;
import static com.google.k2crypto.storage.drivers.K2FileSystemDriver.MAX_FILENAME_LENGTH;

import com.google.k2crypto.K2Context;
import com.google.k2crypto.K2Exception;
import com.google.k2crypto.Key;
import com.google.k2crypto.exceptions.BuilderException;
import com.google.k2crypto.exceptions.KeyVersionException;
import com.google.k2crypto.keyversions.AESKeyVersion;
import com.google.k2crypto.keyversions.HMACKeyVersion;
import com.google.k2crypto.keyversions.KeyVersionRegistry;
import com.google.k2crypto.storage.IllegalAddressException;
import com.google.k2crypto.storage.K2Storage;
import com.google.k2crypto.storage.NoSuitableDriverException;
import com.google.k2crypto.storage.Store;
import com.google.k2crypto.storage.StoreDriver;
import com.google.k2crypto.storage.StoreDriverException;
import com.google.k2crypto.storage.StoreException;
import com.google.k2crypto.storage.StoreIOException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * Unit tests for the K2 native file-system driver.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@RunWith(JUnit4.class)
public class K2FileSystemDriverTest {

  private static final String TESTING_DIRECTORY = "./build/tmp/"; 
  
  private static final String NATIVE_PREFIX = NATIVE_SCHEME + ':'; 
  private static final String NATIVE_POSTFIX = '.' + FILE_EXTENSION;
  
  private static final String FILE_PREFIX = "file:"; 
  
  // To prevent tests from stalling completely if something goes wrong during
  // random generation (of files) 
  private static final int MAX_GENERATION_ATTEMPTS = 100;
 
  // Length of the randomly generated portion of filenames
  private static final int GENERATED_NAME_LENGTH = 64;
  
  private K2Context context = null;
  
  private Random random = null;
  
  private File testingDir = null;
  
  private String testingDirPath = null;

  /**
   * Creates a context for the tests.
   */
  @Before public final void setUp() {
    context = new K2Context();
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
   * Creates an initialized instance of the K2 driver for testing.
   */
  private StoreDriver newDriver() {
    StoreDriver driver = new K2FileSystemDriver();
    driver.initialize(context);
    return driver;
  }
  
  /**
   * Tests that the driver has a valid structure (by attempting to install it).
   */
  @Test public final void testDriverStructure() {
    K2Storage storage = new K2Storage(context);
    try {
      storage.installDriver(K2FileSystemDriver.class);
    } catch (StoreDriverException ex) {
      throw new AssertionError("Driver structure is bad.", ex);
    }
  }
  
  /**
   * Tests that the open() method rejects all syntactically invalid
   * URI addresses.
   */
  @Test public final void testRejectBadAddresses() {
    // Test unsupported components
    checkRejectAddress(FILE_PREFIX + "//host/path",
        IllegalAddressException.Reason.AUTHORITY_UNSUPPORTED);
    checkRejectAddress(FILE_PREFIX + "//user@localhost:80/path",
        IllegalAddressException.Reason.AUTHORITY_UNSUPPORTED);
    checkRejectAddress(FILE_PREFIX + "/path?que",
        IllegalAddressException.Reason.QUERY_UNSUPPORTED);
    checkRejectAddress(FILE_PREFIX + "/path#frag",
        IllegalAddressException.Reason.FRAGMENT_UNSUPPORTED);
    
    // Test invalid schemes
    checkRejectAddress("k3:/path",
        IllegalAddressException.Reason.INVALID_SCHEME);
    checkRejectAddress("keyczar:/path",
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
    checkRejectAddress(NATIVE_PREFIX + "?",
        IllegalAddressException.Reason.MISSING_PATH);
    
    // Test relative path going beyond the logical URI root
    checkRejectAddress("/../my%20key",
        IllegalAddressException.Reason.INVALID_PATH);
    
    final String testingAddress = NATIVE_PREFIX + testingDirPath;
    
    // Test all illegal filename characters
    for (char illegal : new char[] {
        '\0', '\n', '\r', '\t', '\f', '\b', '\\',
        '/', '*', '?', '|', '<', '>', ':', ';', '"'}) {
      String encoded = String.format("%%%02X", (int)illegal);
      assertEquals(3, encoded.length()); // sanity check
      checkRejectAddress(testingAddress + 'A' + encoded + 'Z',
          IllegalAddressException.Reason.INVALID_PATH);
      checkRejectAddress(testingAddress + encoded,
          IllegalAddressException.Reason.INVALID_PATH);
    }
    
    // Test illegal filename prefixes
    for (String illegalPrefix : new String[] { "~", ".", "%20" }) {
      checkRejectAddress(testingAddress + illegalPrefix + "abc",
          IllegalAddressException.Reason.INVALID_PATH);
    }

    // Test illegal filename postfixes
    for (String illegalPostfix : new String[] { ".", "%20" }) {
      checkRejectAddress(testingAddress + "abc" + illegalPostfix,
          IllegalAddressException.Reason.INVALID_PATH);
    }

    // Test filename that is one character too long
    String oneCharTooLongName = generateString(random,
        1 + MAX_FILENAME_LENGTH - NATIVE_POSTFIX.length());
    checkRejectAddress(testingAddress + oneCharTooLongName,
        IllegalAddressException.Reason.INVALID_PATH);
  }
  
  /**
   * Tests that the open() method rejects addresses pointing to a bad 
   * file location (on disk). 
   */
  @Test public final void testRejectBadFileLocation() throws IOException {
    // NOTE: we have to be careful that these tests aren't flaky,
    // since they depend on the file-system state.
    
    // We can only run this test if there is a physical root available
    File[] roots = File.listRoots();
    if (roots != null) {
      // Should not be able to open the root path (without a filename)
      for (File root : roots) {
        checkRejectAddress(NATIVE_PREFIX + root.toURI().getRawPath(),
            IllegalAddressException.Reason.INVALID_PATH);
      }
    }
    
    // The parent "File" of the key file should NOT be a file
    // (i.e. it should be a directory)
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
    for (File f : files) {
      f.deleteOnExit();
    }
    
    // Check that the driver rejects opening the main file address
    // if any of these files is a directory.
    try {
      String mainAddress = NATIVE_PREFIX + files[0].toURI().getRawPath();
      for (File f : files) {
        assertTrue(f.mkdir());
        checkRejectAddress(mainAddress,
            IllegalAddressException.Reason.INVALID_PATH);
        assertTrue(f.delete());
      }
    } finally {
      for (File f : files) {
        f.delete();
      }
    }
  }
  
  private void checkRejectAddress(
      String address, IllegalAddressException.Reason reason) {
    StoreDriver driver = newDriver();
    try {
      driver.open(URI.create(address));
      fail("Should reject " + address);
    } catch (StoreException ex) {
      fail("Unexpected " + ex);
    } catch (IllegalAddressException ex) {
      // Expected
      assertEquals(reason, ex.getReason());
      assertEquals(address, ex.getAddress());
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
    
    String filename = generateSafeFilename(random, testingDir);
    String expected = absTestingAddress + filename;
    
    // Test absolute addresses (with k2: scheme), without and with extension
    checkNormalization(expected,
        absTestingAddress + filename);
    checkNormalization(expected,
        absTestingAddress + filename + NATIVE_POSTFIX);
    
    // Test absolute addresses with collapsable paths, w/o and w/ extension
    checkNormalization(expected,
        absTestingAddress + "anything/./something/.././../" + filename);
    checkNormalization(expected,
        absTestingAddress + "/././" + filename + "");
    
    // Test the above with absolute paths (i.e. no k2: scheme) 
    checkNormalization(expected,
        absTestingPath + filename + NATIVE_POSTFIX);
    checkNormalization(expected,
        absTestingPath + "/./something/../" + filename + NATIVE_POSTFIX);
    
    // Test the above with relative paths
    checkNormalization(expected,
        relTestingPath + filename + NATIVE_POSTFIX);
    checkNormalization(expected,
        relTestingPath + "/anything/../" + filename + NATIVE_POSTFIX);
  }
  
  private void checkNormalization(String expected, String address)
      throws K2Exception {
    StoreDriver driver = newDriver();
    try {
      URI result = driver.open(URI.create(address));
      assertEquals(expected, result.toString());
    } finally {
      driver.close();
    }
  }
  
  @Test public final void testSaveLoadErase() throws K2Exception {
    // Since we aren't testing Key/KeyVersion here,
    // we will just use an empty Key for save/load testing.
    // (NOTE: the procedure to create an empty Key might change later)
    final Key key = new Key();
    
    File[] triple = generateFileTriple(random, testingDir);
    URI address = triple[0].toURI().normalize();
    for (File f : triple) {
      f.deleteOnExit();
    }
    
    StoreDriver driver = newDriver();
    try {
      assertEquals(
          NATIVE_PREFIX + address.getSchemeSpecificPart(),
          driver.open(address) + NATIVE_POSTFIX);
      assertFalse(driver.erase());
      assertTrue(driver.isEmpty());
      assertNull(driver.load());
      
      driver.save(key);
      assertFalse(driver.isEmpty());
      loadAndCheck(driver, key);
      
      assertTrue(driver.erase());
      assertTrue(driver.isEmpty());
      assertNull(driver.load());
      assertFalse(driver.erase());
      
    } finally {
      for (File f : triple) {
        f.delete();
      }
      driver.close();
    }
  }
  
  @Test public final void testRecoverableLoad() throws K2Exception, IOException {
    // Since we aren't testing Key/KeyVersion here,
    // we will just use an empty Key for save/load testing.
    // (NOTE: the procedure to create an empty Key might change later)
    final Key key = new Key();
    
    File[] triple = generateFileTriple(random, testingDir);
    URI address = triple[0].toURI().normalize();
    for (File f : triple) {
      f.deleteOnExit();
    }
    
    StoreDriver driver = newDriver();
    try {
      // Open and save a key
      assertEquals(
          NATIVE_PREFIX + address.getSchemeSpecificPart(),
          driver.open(address) + NATIVE_POSTFIX);
      driver.save(key);
      
      // Verify that we can load when key data is in any slot
      File last = null;
      for (File current : triple) {
        if (last != null) {
          // Move data to next slot
          assertTrue(last.renameTo(current));
          assertFalse(last.exists());
        }
        
        // Check that the slot is readable
        assertTrue(current.isFile());
        loadAndCheck(driver, key);

        // Check it is still readable with corrupted (empty)
        // files in some other slot
        for (File f : triple) {
          if (f != current) {
            assertFalse(f.exists());            
            assertTrue(f.createNewFile());
            loadAndCheck(driver, key);
            assertTrue(f.delete());
          }
        }        
        last = current;
      }
      
      // TODO: test loading precedence (but we need to have key with different data).
      
    } finally {
      for (File f : triple) {
        f.delete();
      }
      driver.close();
    }
  }
  
  private static void loadAndCheck(StoreDriver driver, Key expected)
      throws StoreException {
    assertFalse(driver.isEmpty());
    Key loaded = driver.load();
    assertEquals(
        expected.buildData().build().toByteString(),
        loaded.buildData().build().toByteString());    
  }
  
  @Test public final void testCorruptedLoad() throws K2Exception, IOException {
    File[] triple = generateFileTriple(random, testingDir);
    URI address = triple[0].toURI().normalize();
    for (File f : triple) {
      f.deleteOnExit();
    }
    
    StoreDriver driver = newDriver();
    try {
      // Open the driver
      assertEquals(
          NATIVE_PREFIX + address.getSchemeSpecificPart(),
          driver.open(address) + NATIVE_POSTFIX);

      for (File f : triple) {
        assertFalse(f.exists());
        assertTrue(f.createNewFile());
        checkLoadCorrupted(driver);
        assertTrue(driver.erase());
        assertTrue(driver.isEmpty());
      }

      for (File f : triple) {
        assertFalse(f.exists());
        assertTrue(f.createNewFile());
      }
      checkLoadCorrupted(driver);
      assertTrue(driver.erase());
      assertTrue(driver.isEmpty());
      for (File f : triple) {
        assertFalse(f.exists());
      }      
      
    } finally {
      for (File f : triple) {
        f.delete();
      }
      driver.close();
    }
  }

  private static void checkLoadCorrupted(StoreDriver driver)
      throws StoreException {
    assertFalse(driver.isEmpty());
    try {    
      driver.load();
      fail("Load should fail.");
    } catch (StoreIOException ex) {
      assertEquals(StoreIOException.Reason.DESERIALIZATION_ERROR,
          ex.getReason());
    }
  }
  
  private static String generateSafeFilename(Random random, File dir) {
    String name = generateFileTriple(random, dir)[0].getName();
    return name.substring(0, name.length() - NATIVE_POSTFIX.length());
  }
  
  private static File[] generateFileTriple(Random random, File dir) {
    // Generate the main key file and two temp files for it that do not exist.
    File[] files = new File[3];
    int countdown = MAX_GENERATION_ATTEMPTS;
    do {
      if (--countdown < 0) {
        fail("Could not generate file triple!");
      }
      // Main file
      File main = files[0] =
          generateFile(random, dir, "", NATIVE_POSTFIX);
      // Temp files
      files[1] = new File(dir,
          TEMP_PREFIX + main.getName() + TEMP_A_EXTENSION);
      files[2] = new File(dir,
          TEMP_PREFIX + main.getName() + TEMP_B_EXTENSION);      
    } while (files[1].exists() || files[2].exists());
    return files;
  }
  
  private static File generateFile(
      Random random, File dir, String prefix, String postfix) {
    final int prefixLen = prefix.length();
    final int postfixLen = postfix.length();
    
    // Create an initial random filename
    char[] filename = new char[prefixLen + GENERATED_NAME_LENGTH + postfixLen];
    prefix.getChars(0, prefixLen, filename, 0);
    postfix.getChars(0, postfixLen, filename,
        GENERATED_NAME_LENGTH + prefixLen);
    
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
   * Generates a random string of the given length.
   * 
   * @param random
   * @param length
   * @return
   */
  private static String generateString(Random random, int length) {
    char[] buffer = new char[length];
    for (int i = buffer.length; --i >= 0; ) {
      buffer[i] = (char)('0' + random.nextInt(10)); 
    }
    return new String(buffer);
  }
}
