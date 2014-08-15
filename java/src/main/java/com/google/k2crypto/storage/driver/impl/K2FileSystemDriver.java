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

import static com.google.k2crypto.storage.driver.AddressUtilities.checkNoAuthority;
import static com.google.k2crypto.storage.driver.AddressUtilities.checkNoFragment;
import static com.google.k2crypto.storage.driver.AddressUtilities.checkNoQuery;
import static com.google.k2crypto.storage.driver.AddressUtilities.extractRawPath;

import com.google.k2crypto.Key;
import com.google.k2crypto.K2Context;
import com.google.k2crypto.KeyProto.KeyData;
import com.google.k2crypto.exceptions.InvalidKeyDataException;
import com.google.k2crypto.exceptions.UnregisteredKeyVersionException;
import com.google.k2crypto.keyversions.KeyVersionRegistry;
import com.google.k2crypto.storage.IllegalAddressException;
import com.google.k2crypto.storage.StoreException;
import com.google.k2crypto.storage.StoreIOException;
import com.google.k2crypto.storage.driver.ReadableDriver;
import com.google.k2crypto.storage.driver.Driver;
import com.google.k2crypto.storage.driver.DriverInfo;
import com.google.k2crypto.storage.driver.WritableDriver;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.ExtensionRegistry;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.util.regex.Pattern;

/**
 * K2-native local file-system key storage driver.
 * 
 * <p>This driver will save/load keys to a local file with a {@code .k2k}
 * extension in a directory specified by the storage address, which can be in
 * one of the following formats:
 * <ul>
 * <li>{@code k2:{ABSOLUTE PATH}filename[.k2k]}  
 * <li>{@code file:{ABSOLUTE PATH}filename.k2k}  
 * <li>{@code {ABSOLUTE/RELATIVE PATH}filename.k2k}  
 *  </ul>
 * 
 * <p>Temporary/backup files are used to minimize the possibility of data-loss
 * when saving a key and to maximize the chance of recovery when loading a key.
 * 
 * <p>The current implementation does NOT acquire an OS-level lock on the key
 * file, so it is possible for two instances of the driver, possibly on
 * different VMs, to open the same key location. In this scenario, concurrent
 * writes on the two instances will have undefined behavior.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@DriverInfo(
    id = K2FileSystemDriver.NATIVE_SCHEME,
    name = "K2 Native File-System Driver",
    version = "0.1")
public class K2FileSystemDriver 
    implements Driver, ReadableDriver, WritableDriver {
  
  // TODO(darylseah): implement WrappingDriver when the Key usage API is stable
  
  /**
   * File extension that will be appended to key files.
   */
  public static final String FILE_EXTENSION = "k2k"; // "K2 Key"
  
  /**
   * Name of the native scheme in use (also the identifier of the driver).
   */
  static final String NATIVE_SCHEME = "k2";
  
  /**
   * Name of the alternative file scheme that this driver accepts.
   */
  static final String FILE_SCHEME = "file";

  /**
   * File extension appended to the first temporary file.
   */
  static final String TEMP_A_EXTENSION = ".000";
  
  /**
   * File extension appended to the second temporary file.
   */
  static final String TEMP_B_EXTENSION = ".111";
  
  /**
   * Prefix appended to both temporary filenames.
   */
  static final String TEMP_PREFIX = ".";
  
  /**
   * Maximum length of the name of the main key file, excluding the extension.
   */
  static final int MAX_FILENAME_LENGTH = 255 
      - (FILE_EXTENSION.length() + 1) - TEMP_PREFIX.length()
      - Math.max(TEMP_A_EXTENSION.length(), TEMP_B_EXTENSION.length());

  // Regex fragment excluding \, /, *, ?, |, <, >, :, ;, ", control characters
  // and vertical spaces from filenames
  private static final String FILENAME_EXCLUSIONS =
      "\\p{Zl}\\p{Zp}\\p{C}\\u0000-\\u001F\\u007F"
          + Pattern.quote("\\/*?|<>:;\"");
  
  // Regex matching a valid filename. Summary:
  //   - Do not start with '~' or '.' or any spaces.
  //   - Do not end with '.' or any spaces before the file extension.
  //   - Must not include any filename exclusions (above).
  //   - The file extension is case-sensitive.
  //   - Length without extension must not exceed MAX_FILENAME_LENGTH.
  private static final Pattern FILENAME_REGEX =
      Pattern.compile("^(?![\\p{Z}\\~\\.])"
          + "[^" + FILENAME_EXCLUSIONS + "]{1," + MAX_FILENAME_LENGTH + "}" 
          + "(?<![\\p{Z}\\.])"
          + "\\." + Pattern.quote(FILE_EXTENSION) + '$');

  // Regex for checking if the address path already has the file extension.
  private static final Pattern EXTENSION_REGEX = Pattern.compile(
      "\\." + Pattern.quote(FILE_EXTENSION) + '$', Pattern.CASE_INSENSITIVE); 
  
  // Context for the current K2 session
  private K2Context context;
  
  // Main file that the key should be written to/read from
  private File keyFile;
  
  // Temporary file slots for writing (also used as backups when reading)
  private File tempFileA;
  private File tempFileB;
  
  /**
   * @see Driver#initialize(K2Context)
   */
  public void initialize(K2Context context) {
    this.context = context;
  }

  /**
   * @see Driver#open(java.net.URI)
   */
  public URI open(final URI address) throws IllegalAddressException {
    // Check for unsupported components in the address
    // (we only accept a scheme + path)
    checkNoAuthority(address);
    checkNoQuery(address);
    checkNoFragment(address);

    // Check that we either have an empty, file or native scheme 
    final boolean mustHaveExtension;
    String scheme = address.getScheme();
    if (scheme == null || scheme.equalsIgnoreCase(FILE_SCHEME)) {
      // The empty and file schemes are generic,  so there should be a
      // qualifying extension that tells us we are accessing a k2 key file.
      mustHaveExtension = true;
    } else if (NATIVE_SCHEME.equalsIgnoreCase(scheme)) {
      // If the "k2" scheme is specified, the path need not have the extension.
      mustHaveExtension = false;
    } else {
      // Unrecognized scheme
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.INVALID_SCHEME, null);
    }
    
    // Extract path. We are assuming (below) that any encoded unreserved
    // characters have already been decoded by K2Storage.
    String path = extractRawPath(address);
    
    // Check if the file extension is included in the path.
    if (!EXTENSION_REGEX.matcher(path).find()) {
      if (mustHaveExtension) {
        throw new IllegalAddressException(
            address, IllegalAddressException.Reason.INVALID_PATH, null);
      }
      // Append if missing
      path = path + '.' + FILE_EXTENSION;
    }
    
    try {
      // Resolve the disk address of the provided path
      final URI diskAddress = new File("").toURI().resolve(path).normalize();
      
      // Create all file objects before checking
      final File pri = new File(diskAddress);
      final File parent = pri.getParentFile();
      final String filename = pri.getName();
      final File tmpA =
          new File(parent, TEMP_PREFIX + filename + TEMP_A_EXTENSION); 
      final File tmpB =
          new File(parent, TEMP_PREFIX + filename + TEMP_B_EXTENSION);
      
      // Grab path from the file for checking and later usage
      path = pri.toURI().getRawPath();
      
      // Filename should be a valid
      if (FILENAME_REGEX.matcher(filename).matches()
          // Path should be absolute after normalization 
          && !path.startsWith("/../")
          // Parent file should be an existing directory
          && parent != null && parent.isDirectory()
          // Everything else should NOT be a directory
          && !pri.isDirectory() && !tmpA.isDirectory() && !tmpB.isDirectory()) {
        
        // All OK. Generate final address with scheme and without extension.
        path = path.substring(0, path.length() - FILE_EXTENSION.length() - 1);
        URI finalAddress = URI.create(NATIVE_SCHEME + ':' + path);

        // Initialize the driver.
        this.keyFile = pri;
        this.tempFileA = tmpA;
        this.tempFileB = tmpB;
        return finalAddress;
      }
    } catch (IllegalArgumentException ex) {
      // The path is invalid (from URI.create or new File).
      // Fall-through for exception throw.
    }
    
    // Falling through to here implies the path is invalid
    throw new IllegalAddressException(address,
        IllegalAddressException.Reason.INVALID_PATH, null);
  }

  /**
   * @see Driver#close()
   */
  public void close() {
    // Free file resources.
    context = null;
    keyFile = null;
    tempFileA = null;
    tempFileB = null;
  }

  /**
   * @see ReadableDriver#isEmpty()
   */
  public boolean isEmpty() throws StoreException {
    return !(keyFile.isFile() || tempFileA.isFile() || tempFileB.isFile());
  }

  /**
   * @see WritableDriver#save(Key)
   */
  public void save(Key key) throws StoreException {
    // Dump key to bytes first
    byte[] keyBytes = serializeKey(key);
    
    // Replace primary key file in a fault-tolerant manner
    if (keyFile.isFile()) {
      // Primary exists; pick a temp slot to write to
      File target =
          (isFormerMoreReadable(tempFileA, tempFileB) ? tempFileB : tempFileA);
      File other = (target == tempFileB ? tempFileA : tempFileB);
      
      // Both temp slots exist => something went really wrong last time
      if (target.isFile() && other.isFile()) {
        // Spend some effort to make sure the 'other' slot is readable, because
        // that will be our backup if something goes wrong in this write.
        try {
          readKey(other, context.getKeyVersionRegistry().getProtoExtensions());
        } catch (Exception ex) {
          // Looks like the 'other' slot is NOT readable,
          // swap so that we write to this slot instead.
          File temp = other;
          other = target;
          target = temp;
        }
      }

      // Write to 'target' slot, then delete 'other' slot if successful
      writeKey(keyBytes, target);
      other.delete();
      
      // Move primary to the now empty 'other' slot,
      // then move 'target' slot to the primary. 
      if (!keyFile.renameTo(other) || !target.renameTo(keyFile)) {
        throw new StoreIOException(
            StoreIOException.Reason.WRITE_ERROR);
      }
      
    } else {
      // Primary does not exist; just write directly to the primary slot
      writeKey(keyBytes, keyFile);
    }
    
    // Successful; clean up temp slots
    tempFileA.delete();
    tempFileB.delete();
  }
  
  /**
   * Converts the key to bytes.
   * 
   * @param key Key to serialize.
   * 
   * @return an exact byte array containing the serialized key. 
   * 
   * @throws StoreIOException if there is an error serializing the key.
   */
  private static byte[] serializeKey(Key key) throws StoreIOException {
    try {
      KeyData data = key.buildData().build();
      byte[] bytes = new byte[data.getSerializedSize()];
      CodedOutputStream cos = CodedOutputStream.newInstance(bytes);
      data.writeTo(cos);
      cos.checkNoSpaceLeft();
      return bytes;
    } catch (Exception ex) {
      throw new StoreIOException(
          StoreIOException.Reason.SERIALIZATION_ERROR, ex);
    }
  }
  
  /**
   * Writes the bytes of the key to a given file. 
   * 
   * @param keyBytes Bytes of the key to write.
   * @param file Target file to write to.
   * 
   * @throws StoreIOException if there is an error while writing.
   */
  private void writeKey(byte[] keyBytes, File file) throws StoreIOException {
    IOException exception = null;
    FileOutputStream out = null;
    try {
      out = new FileOutputStream(file);
      out.write(keyBytes);
      out.flush();
    } catch (IOException ex) {
      exception = ex;
    } finally {
      try { out.close(); }
      catch (Exception ex) {}
    }
    if (exception != null || file.length() != keyBytes.length) {
      file.delete();
      throw new StoreIOException(
          StoreIOException.Reason.WRITE_ERROR, exception);
    }
  }
  
  /**
   * @see ReadableDriver#load()
   */
  public Key load() throws StoreException {
    // If all the candidate files for a key are non-existent,
    // there is nothing to load.
    if (isEmpty()) {
      return null;
    }
    
    // Prioritize candidate files for reading
    File[] candidates = isFormerMoreReadable(tempFileA, tempFileB) ?
        new File[] { keyFile, tempFileA, tempFileB } :
        new File[] { keyFile, tempFileB, tempFileA };
    
    // Attempt to read each file and return the first successfully parsed Key
    ExtensionRegistry registry =
        context.getKeyVersionRegistry().getProtoExtensions();
    StoreIOException ioException = null;
    for (File file : candidates) {
      try {
        if (file != null) {
          return readKey(file, registry);
        }
      } catch (StoreIOException ex) {
        // Retain the highest-level exception (i.e. the furthest we have gotten)
        if (ioException == null
            || ex.getReason().compareTo(ioException.getReason()) < 0) {
          ioException = ex;
        }
      }
    }
    
    // If all files failed, throw the recorded exception
    assert(ioException != null);
    throw ioException;
  }
  
  /**
   * Reads a key from the given file. 
   * 
   * @param file File to read from.
   * @param registry Protobuf extension registry obtained
   *                 from {@link KeyVersionRegistry}.
   *                 
   * @return the deserialized key if successful.
   * 
   * @throws StoreIOException if there is an error at any stage of the process.
   */
  private Key readKey(File file, ExtensionRegistry registry)
      throws StoreIOException {
    FileInputStream in = null;
    try {
      in = new FileInputStream(file);
      return new Key(context, KeyData.parseFrom(in, registry));
    } catch (IOException ex) {
      throw new StoreIOException(
          StoreIOException.Reason.READ_ERROR, ex);
    } catch (InvalidKeyDataException ex) {
      throw new StoreIOException(
          StoreIOException.Reason.DESERIALIZATION_ERROR, ex);
    } catch (UnregisteredKeyVersionException ex) {
      throw new StoreIOException(
          StoreIOException.Reason.UNREGISTERED_KEY_VERSION, ex);
    } finally {
      try { in.close(); }
      catch (Exception ex) {}
    }
  }
  
  /**
   * @see WritableDriver#erase()
   */
  public boolean erase() throws StoreException {
    // Intentional use of non-short circuiting OR to delete everything.
    return keyFile.delete() | tempFileA.delete() | tempFileB.delete();
  }
  
  /**
   * Evaluates whether the first file is likely more "readable" than the second.
   * 
   * <p>We do this by heuristically comparing the attributes of the files,
   * without actually attempting a read.  
   * 
   * @param f1 First file.
   * @param f2 Second file.
   * 
   * @return {@code true} if the first file is more readable,
   *         {@code false} otherwise.
   */
  private static boolean isFormerMoreReadable(File f1, File f2) {
    int cmp;
    if ((cmp = Boolean.compare(f1.isFile(), f2.isFile())) != 0
        || (cmp = Boolean.compare(f1.canRead(), f2.canRead())) != 0
        || (cmp = Long.compare(f1.lastModified(), f2.lastModified())) != 0
        || (cmp = Long.compare(f1.length(), f2.length())) != 0) { 
      return cmp > 0;
    }
    return false;
  }
}
