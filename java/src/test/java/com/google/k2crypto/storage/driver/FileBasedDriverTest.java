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

package com.google.k2crypto.storage.driver;

import static org.junit.Assert.fail;

import com.google.k2crypto.storage.driver.Driver;

import org.junit.Before;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.util.Random;

/**
 * Boilerplate class for a file-based storage driver JUnit test.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public abstract class FileBasedDriverTest<T extends Driver> 
    extends BasicDriverTest<T> {

  // Directory for the driver to read/write test key files
  private static final String TESTING_DIRECTORY = "./build/tmp/"; 
  
  // Limit to prevent tests from stalling completely if something goes wrong
  // during random generation of test files 
  private static final int MAX_GENERATION_ATTEMPTS = 100;
 
  // Length of the randomly generated portion of filenames
  private static final int GENERATED_NAME_LENGTH = 64;
  
  // File object form of the testing directory
  private File testingDir;
  
  // Absolute path of the testing directory (percent-encoded)
  private String testingDirPath;
  
  /**
   * Initializes the file-based driver testing boilerplate. 
   * 
   * @param driverClass Driver implementation being tested.
   */
  protected FileBasedDriverTest(Class<T> driverClass) {
    super(driverClass);
  }
  
  /**
   * Returns a File object pointing to the testing directory.
   */
  protected File getTestingDir() {
    return testingDir;
  }
  
  /**
   * Returns the absolute percent-encoded path of the testing directory.
   * 
   * <p>The path is guaranteed to terminate with a {@code '/'}.
   */
  protected String getTestingDirPath() {
    return testingDirPath;
  }

  /**
   * Returns the relative percent-encoded path of the testing directory,
   * with respect to the current directory.
   * 
   * <p>The path is guaranteed to terminate with a {@code '/'}.
   */
  protected String getRelativeTestingDirPath() {
    return TESTING_DIRECTORY;
  }

  /**
   * Initializes the working directory for test files.
   */
  @Before public void setupTestDirectory() {
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
   * Generates a file that does not currently exist.
   * 
   * @param dir Directory that the file should be in.
   * @param prefix String to append at the start of the generated filename.
   * @param postfix String to append at the end of the generated filename.
   * 
   * @return a non-existent file in the given directory.
   */
  protected File generateFile(File dir, String prefix, String postfix) {
    Random random = getSharedRandom();
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
   * Copies a file. 
   * 
   * @param source File to copy.
   * @param destination The copy to create.
   */
  protected static void copyData(File source, File destination) {
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
  protected static void deleteAllOnExit(File ... files) {
    for (File f : files) {
      f.deleteOnExit();
    }
  }
  
  /**
   * Deletes the given files immediately.  
   * 
   * @param files Files to delete.
   */
  protected static void deleteAll(File ... files) {
    for (File f : files) {
      f.delete();
    }
  }
}
