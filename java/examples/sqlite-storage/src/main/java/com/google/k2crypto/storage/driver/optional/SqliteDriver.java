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

import static com.google.k2crypto.storage.driver.AddressUtilities.checkNoAuthority;
import static com.google.k2crypto.storage.driver.AddressUtilities.checkNoQuery;
import static com.google.k2crypto.storage.driver.AddressUtilities.extractRawPath;
import static com.google.k2crypto.storage.driver.AddressUtilities.extractFragment;

import com.google.k2crypto.Key;
import com.google.k2crypto.K2Context;
import com.google.k2crypto.KeyProto.KeyData;
import com.google.k2crypto.exceptions.InvalidKeyDataException;
import com.google.k2crypto.exceptions.UnregisteredKeyVersionException;
import com.google.k2crypto.storage.IllegalAddressException;
import com.google.k2crypto.storage.StoreException;
import com.google.k2crypto.storage.StoreIOException;
import com.google.k2crypto.storage.driver.ReadableDriver;
import com.google.k2crypto.storage.driver.Driver;
import com.google.k2crypto.storage.driver.DriverInfo;
import com.google.k2crypto.storage.driver.WritableDriver;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistry;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.regex.Pattern;

/**
 * SQLite driver implementation for K2 key storage.
 * 
 * <p>This driver saves/loads keys to a {@code Keys} table (automatically
 * generated) in the SQLite database file specified by the address.
 * It accepts addresses only with the following format:
 * {@code sqlite:{ABSOLUTE PATH TO DATABASE FILE}#{KEY ID}} 
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@DriverInfo(
    id = SqliteDriver.SCHEME,
    name = "SQLite Storage Driver",
    version = "0.1")
public class SqliteDriver implements Driver, ReadableDriver, WritableDriver {

  /**
   * Name of the scheme and identifier of the driver.
   */
  static final String SCHEME = "sqlite";
  
  /**
   * Maximum length of the key identifier (URI fragment).
   */
  static final int MAX_KEY_ID_LENGTH = 255;

  // Regex matching a valid database filename. Rules:
  //   - Do not start with '~' or '.' or any spaces.
  //   - Do not end with '.' or any spaces
  //   - No control characters, vertical spaces or any in '\/*?|<>:;"'
  private static final Pattern DB_FILENAME_REGEX =
      Pattern.compile("^(?![\\p{Z}\\~\\.])"
          + "[^\\p{Zl}\\p{Zp}\\p{C}\\u0000-\\u001F\\u007F"
            + Pattern.quote("\\/*?|<>:;\"") + "]+"
          + "(?<![\\p{Z}\\.])$");

  // Regex matching a valid key identifier. Rules:
  //   - Do not start or end with spaces.
  //   - No control characters or vertical spaces.
  //   - Maximum length is 255 characters.
  private static final Pattern KEY_ID_REGEX =
      Pattern.compile("^(?![\\p{Z}])"
          + "[^\\p{Zl}\\p{Zp}\\p{C}\\u0000-\\u001F\\u007F]"
          + "{1," + MAX_KEY_ID_LENGTH + "}"
          + "(?<![\\p{Z}])$");
  
  // Constant returned by queryKey() for an existing key if data is not required
  private static final byte[] KEY_EXISTS = new byte[0];
  
  // Context for the current K2 session
  private K2Context context;
  
  // Connection to the SQLite DB
  private Connection connection;
  
  // Identifier (table primary key) of the key to save/load
  private String keyIdentifier;
  
  // Prepared statements that are created on demand and cached
  private PreparedStatement selectStmt;
  private PreparedStatement insertStmt;
  private PreparedStatement deleteStmt;
  
  /**
   * @see Driver#initialize(K2Context)
   */
  public void initialize(K2Context context) {
    this.context = context;
  }

  /**
   * @see Driver#open(java.net.URI)
   */
  public URI open(final URI address)
      throws StoreException, IllegalAddressException {
    
    // Make sure the SQLite JDBC driver is loaded
    try {
      Class.forName("org.sqlite.JDBC").newInstance();
    } catch (Exception ex) {
      throw new StoreException("SQLite JDBC not available.", ex);
    }

    // Check for unsupported components in the address and scheme.
    // (we only accept/require a scheme + path + fragment)
    checkNoAuthority(address);
    checkNoQuery(address);
    checkScheme(address);
    
    final String keyIdentifier = extractKeyIdentifier(address);
    final String path = extractRawPath(address);
    try {
      // Locate the database file specified by the path
      final File dbFile =
          new File(new File("").toURI().resolve(path).normalize());
      final File parent = dbFile.getParentFile();
      final String filename = dbFile.getName();
      
      // If it does not exist, the parent directory must exist
      if (dbFile.isFile() || (parent != null
          && parent.isDirectory() && !dbFile.isDirectory())
          // The database file must also match the pattern for portability
          && DB_FILENAME_REGEX.matcher(filename).matches()) {
        
        // Reconstitute the URI for returning to the user
        final URI fileAddress = dbFile.toURI();
        final URI finalAddress = URI.create(SCHEME + ':' 
            + fileAddress.getRawPath() + '#' + address.getRawFragment());
        
        // Attempt opening a connection to the database file
        Connection connection = openConnection(fileAddress.getPath());

        // Everything seems OK. Set open state and return.
        this.connection = connection;
        this.keyIdentifier = keyIdentifier;
        return finalAddress;
      }
    } catch (SQLException ex) {
      // SQL-specific error
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.DRIVER_SPECIFIC, ex);
    } catch (IllegalArgumentException ex) {
      // The path is invalid (from URI.create or new File).
      // Fall-through for exception throw.
    }
    
    // Falling through to here implies the path is invalid
    throw new IllegalAddressException(address,
        IllegalAddressException.Reason.INVALID_PATH, null);
  }
  
  /**
   * Checks that the scheme is identical to the driver identifier.
   *  
   * @param address Address to check.
   * 
   * @throws IllegalAddressException if the address has an invalid scheme.
   */
  private void checkScheme(URI address) throws IllegalAddressException {
    if (!SCHEME.equalsIgnoreCase(address.getScheme())) {
      // Unrecognized scheme
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.INVALID_SCHEME, null);
    }
  }
  
  /**
   * Opens a connection to the database and creates the keys table for storage
   * if it does not already exist. 
   * 
   * @param dbFilePath Path to the SQLite database file on disk.
   * 
   * @return the opened connection.
   * 
   * @throws SQLException if there is some issue opening the connection.
   */
  private Connection openConnection(String dbFilePath) throws SQLException {
    Connection connection =
        DriverManager.getConnection("jdbc:sqlite:" + dbFilePath);
    Statement stmt = null;
    try {
      // Create the Keys table if it does not already exist
      stmt = connection.createStatement();
      stmt.executeUpdate(
          "CREATE TABLE IF NOT EXISTS Keys ("
              + "id VARCHAR(" + MAX_KEY_ID_LENGTH + ") PRIMARY KEY, "
              + "data BLOB NOT NULL, "
              + "modified DATETIME NOT NULL)");
      
    } catch (SQLException ex) {
      // Unexpected error, close connection and throw to other handler
      try { connection.close(); }
      catch (Exception e) {}
      throw ex;
    } finally {
      // Close temp. statement
      try { stmt.close(); }
      catch (Exception e) {}
    }
    return connection;
  }

  /**
   * Extracts (and verifies) the key id from the fragment of the address.
   *  
   * @param address Address to obtain the identifier from.
   */
  private String extractKeyIdentifier(URI address)
      throws IllegalAddressException {
    final String keyIdentifier = extractFragment(address);
    if (!KEY_ID_REGEX.matcher(keyIdentifier).matches()) {
      // Fragment (specifying the key id) is invalid
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.INVALID_FRAGMENT, null);      
    }
    return keyIdentifier;
  }
  
  /**
   * @see Driver#close()
   */
  public void close() {
    // Free basic resources
    context = null;
    keyIdentifier = null;
    try {
      // Explicitly free all DB resources and ignore any closing exceptions
      try { insertStmt.close(); }
      catch (Exception ex) {}
      try { selectStmt.close(); }
      catch (Exception ex) {}
      try { deleteStmt.close(); }
      catch (Exception ex) {}
      try { connection.close(); }
      catch (Exception ex) {}
    } finally {
      insertStmt = null;
      selectStmt = null;
      deleteStmt = null;
      connection = null;
    }
  }

  /**
   * Queries the database for the key data.
   * 
   * @param retrieveData {@code true} if actual key data should be returned,
   *                     {@code false} to just return a non-null.
   *                      
   * @return if the key exists, a byte array of the actual key data or a
   *         non-null, depending on the {@code retrieveData} argument.
   *         {@code null} if the key does not exist.
   *         
   * @throws StoreIOException if there is any error executing the query.
   */
  private byte[] queryKey(boolean retrieveData) throws StoreIOException {
    // Obtain cached statement
    PreparedStatement stmt = selectStmt;
    if (stmt == null) {
      try {
        // Prepare if not cached
        stmt =
            connection.prepareStatement("SELECT data FROM Keys WHERE id = ?");
        stmt.setString(1, keyIdentifier);
      } catch (SQLException ex) {
        throw new StoreIOException(StoreIOException.Reason.DRIVER_SPECIFIC, ex);
      }
      selectStmt = stmt;
    }

    // Execute query and return data if requested
    ResultSet results = null;
    try {
      results = stmt.executeQuery();
      if (results.next()) {
        return retrieveData ? results.getBytes(1) : KEY_EXISTS;
      }
    } catch (SQLException ex) {
      throw new StoreIOException(StoreIOException.Reason.READ_ERROR, ex);
    } finally {
      try { results.close(); }
      catch (Exception ex) {}
    }
    return null;
  }
  
  /**
   * @see ReadableDriver#isEmpty()
   */
  public boolean isEmpty() throws StoreException {
    return queryKey(false) == null;
  }

  /**
   * @see ReadableDriver#load()
   */
  public Key load() throws StoreException {
    byte[] bytes = queryKey(true);
    if (bytes == null) {
      return null;
    }
    
    // Deserialize bytes of loaded key
    ExtensionRegistry registry =
        context.getKeyVersionRegistry().getProtoExtensions();
    try {
      return new Key(context, KeyData.parseFrom(bytes, registry));
    } catch (IOException ex) {
      throw new StoreIOException(
          StoreIOException.Reason.READ_ERROR, ex);
    } catch (InvalidKeyDataException ex) {
      throw new StoreIOException(
          StoreIOException.Reason.DESERIALIZATION_ERROR, ex);
    } catch (UnregisteredKeyVersionException ex) {
      throw new StoreIOException(
          StoreIOException.Reason.UNREGISTERED_KEY_VERSION, ex);
    }
  }
  
  /**
   * @see WritableDriver#save(Key)
   */
  public void save(Key key) throws StoreException {
    // Obtain cached statement
    PreparedStatement stmt = insertStmt;
    if (stmt == null) {
      try {
        // Prepare if not cached
        stmt = connection.prepareStatement(
            "INSERT OR REPLACE INTO Keys (id, data, modified) "
            + "VALUES (?, ?, datetime('now'))");
        stmt.setString(1, keyIdentifier);
      } catch (SQLException ex) {
        throw new StoreIOException(StoreIOException.Reason.DRIVER_SPECIFIC, ex);
      }
      insertStmt = stmt;
    }
    
    // Convert key contents to byte array
    ByteString bytes;
    try {
      bytes = key.buildData().build().toByteString();
    } catch (RuntimeException ex) {
      throw new StoreIOException(
          StoreIOException.Reason.SERIALIZATION_ERROR, ex);
    }
    
    // Insert/update key in database table
    try {
      stmt.setBytes(2, bytes.toByteArray());
      stmt.executeUpdate();
    } catch (SQLException ex) {
      throw new StoreIOException(StoreIOException.Reason.WRITE_ERROR, ex);
    }    
  }

  /**
   * @see WritableDriver#erase()
   */
  public boolean erase() throws StoreException {
    // Obtain cached statement
    PreparedStatement stmt = deleteStmt;
    if (stmt == null) {
      try {
        // Prepare if not cached
        stmt = connection.prepareStatement("DELETE FROM Keys WHERE id = ?");
        stmt.setString(1, keyIdentifier);
      } catch (SQLException ex) {
        throw new StoreIOException(StoreIOException.Reason.DRIVER_SPECIFIC, ex);
      }
      deleteStmt = stmt;
    }
    
    // Remove key from database table
    try {
      return stmt.executeUpdate() > 0;
    } catch (SQLException ex) {
      throw new StoreIOException(StoreIOException.Reason.WRITE_ERROR, ex);
    }
  }
}
