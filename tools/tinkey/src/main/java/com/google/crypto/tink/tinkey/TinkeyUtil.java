// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.tinkey;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.BinaryKeysetWriter;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetManager;
import com.google.crypto.tink.KeysetReader;
import com.google.crypto.tink.KeysetWriter;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/** Various helpers. */
final class TinkeyUtil {
  public enum CommandType {
    ADD_KEY,
    CONVERT_KEYSET,
    CREATE_KEYSET,
    CREATE_PUBLIC_KEYSET,
    LIST_KEY_TEMPLATES,
    DELETE_KEY,
    DESTROY_KEY,
    DISABLE_KEY,
    ENABLE_KEY,
    LIST_KEYSET,
    ROTATE_KEYSET,
    PROMOTE_KEY
  }

  /** Creates a {@code KeysetReader} that can read the keyset in the right {@code inFormat}. */
  public static KeysetReader createKeysetReader(InputStream inputStream, String inFormat)
      throws IOException {
    if (inFormat == null || inFormat.toLowerCase().equals("json")) {
      return JsonKeysetReader.withInputStream(inputStream);
    }
    return BinaryKeysetReader.withInputStream(inputStream);
  }

  /** Creates a {@code KeysetWriter} that can write the keyset in the right {@code outFormat}. */
  public static KeysetWriter createKeysetWriter(OutputStream outputStream, String outFormat)
      throws IOException {
    if (outFormat == null || outFormat.toLowerCase().equals("json")) {
      return JsonKeysetWriter.withOutputStream(outputStream);
    }
    return BinaryKeysetWriter.withOutputStream(outputStream);
  }

  /**
   * Creates a keyset that contains a single key of template {@code keyTemplate}, encrypts it using
   * {@code credentialPath} and {@code masterKeyUri}, then encodes it in {@code outFormat}.
   *
   * @return an input stream containing the resulting encrypted keyset.
   * @throws GeneralSecurityException if failed to encrypt keyset.
   */
  public static final InputStream createKeyset(
      KeyTemplate keyTemplate, String outFormat, String masterKeyUri, String credentialPath)
      throws GeneralSecurityException, IOException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    createKeyset(outputStream, outFormat, masterKeyUri, credentialPath, keyTemplate);
    return new ByteArrayInputStream(outputStream.toByteArray());
  }

  /**
   * Creates a keyset that contains a single key of template {@code keyTemplate}, encrypts it using
   * {@code credentialPath} and {@code masterKeyUri}, then writes it to {@code writer}.
   */
  public static void createKeyset(
      OutputStream outputStream,
      String outFormat,
      String masterKeyUri,
      String credentialPath,
      KeyTemplate keyTemplate)
      throws GeneralSecurityException, IOException {
    @SuppressWarnings("deprecation") // Need to maintain backward-compatibility
    KeysetHandle handle =
        KeysetManager.withEmptyKeyset().rotate(toProto(keyTemplate)).getKeysetHandle();

    writeKeyset(handle, outputStream, outFormat, masterKeyUri, credentialPath);
  }

  /** Manipulates a key within a keyset. */
  public static void manipulateKey(
      CommandType type,
      OutputStream outputStream,
      String outFormat,
      InputStream inputStream,
      String inFormat,
      String masterKeyUri,
      String credentialPath,
      int keyId)
      throws GeneralSecurityException, IOException {
    KeysetManager manager =
        KeysetManager.withKeysetHandle(
            getKeysetHandle(inputStream, inFormat, masterKeyUri, credentialPath));
    switch (type) {
      case DELETE_KEY:
        manager = manager.delete(keyId);
        break;
      case DESTROY_KEY:
        manager = manager.destroy(keyId);
        break;
      case DISABLE_KEY:
        manager = manager.disable(keyId);
        break;
      case ENABLE_KEY:
        manager = manager.enable(keyId);
        break;
      case PROMOTE_KEY:
        manager = manager.setPrimary(keyId);
        break;
      default:
        throw new GeneralSecurityException("invalid command");
    }

    writeKeyset(manager.getKeysetHandle(), outputStream, outFormat, masterKeyUri, credentialPath);
  }

  /**
   * Creates and adds a new key to an existing keyset. The new key becomes the primary key if {@code
   * type} is {@link CommandType#ROTATE}.
   */
  public static void createKey(
      CommandType type,
      OutputStream outputStream,
      String outFormat,
      InputStream inputStream,
      String inFormat,
      String masterKeyUri,
      String credentialPath,
      KeyTemplate keyTemplate)
      throws GeneralSecurityException, IOException {
    KeysetManager manager =
        KeysetManager.withKeysetHandle(
            getKeysetHandle(inputStream, inFormat, masterKeyUri, credentialPath));
    switch (type) {
      case ADD_KEY:
        manager.add(keyTemplate);
        break;
      case ROTATE_KEYSET:
        manager.rotate(toProto(keyTemplate));
        break;
      default:
        throw new GeneralSecurityException("invalid command");
    }

    writeKeyset(manager.getKeysetHandle(), outputStream, outFormat, masterKeyUri, credentialPath);
  }

  // TODO(b/153937575): remove this once KeysetManager allows to directly work with KeyTemplate
  // POJO.
  private static com.google.crypto.tink.proto.KeyTemplate toProto(KeyTemplate template) {
    OutputPrefixType prefixType;

    switch (template.getOutputPrefixType()) {
      case TINK:
        prefixType = OutputPrefixType.TINK;
        break;
      case LEGACY:
        prefixType = OutputPrefixType.LEGACY;
        break;
      case RAW:
        prefixType = OutputPrefixType.RAW;
        break;
      case CRUNCHY:
        prefixType = OutputPrefixType.CRUNCHY;
        break;
      default:
        throw new IllegalArgumentException("Unknown output prefix type");
    }

    return com.google.crypto.tink.proto.KeyTemplate.newBuilder()
        .setTypeUrl(template.getTypeUrl())
        .setValue(ByteString.copyFrom(template.getValue()))
        .setOutputPrefixType(prefixType)
        .build();
  }

  /**
   * Writes the keyset managed by {@code handle} to {@code outputStream} with format {@code
   * outFormat}. Maybe encrypt it with {@code masterKeyUri} and {@code credentialPath}.
   */
  public static void writeKeyset(
      KeysetHandle handle,
      OutputStream outputStream,
      String outFormat,
      String masterKeyUri,
      String credentialPath)
      throws GeneralSecurityException, IOException {
    KeysetWriter writer = createKeysetWriter(outputStream, outFormat);
    if (masterKeyUri != null) {
      Aead masterKey =
          KmsClients.getAutoLoaded(masterKeyUri)
              .withCredentials(credentialPath)
              .getAead(masterKeyUri);
      handle.write(writer, masterKey);
    } else {
      CleartextKeysetHandle.write(handle, writer);
    }
  }

  /**
   * Returns a {@code KeysetHandle} from either a cleartext {@code Keyset} or a {@code
   * EncryptedKeyset}, read from {@code inputStream}.
   */
  public static KeysetHandle getKeysetHandle(
      InputStream inputStream, String inFormat, String masterKeyUri, String credentialPath)
      throws IOException, GeneralSecurityException {
    KeysetReader reader = createKeysetReader(inputStream, inFormat);
    if (masterKeyUri != null) {
      Aead masterKey =
          KmsClients.getAutoLoaded(masterKeyUri)
              .withCredentials(credentialPath)
              .getAead(masterKeyUri);
      return KeysetHandle.read(reader, masterKey);
    }
    return CleartextKeysetHandle.read(reader);
  }

  /**
   * Checks that input or output format is valid. Only supported formats are {@code json} and {@code
   * binary} (case-insensitive).
   *
   * @throws IllegalArgumentException iff format is invalid
   */
  public static void validateFormat(String format) throws IllegalArgumentException {
    if (format != null
        && !format.toLowerCase().equals("json")
        && !format.toLowerCase().equals("binary")) {
      throw new IllegalArgumentException("invalid format: " + format);
    }
  }

  /** Prints an error then exits. */
  public static void die(String error) {
    System.err.print(String.format("Error: %s\n", error));
    System.exit(1);
  }

  private TinkeyUtil() {}
}
