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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetManager;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Locale;

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

  private static boolean isJson(String outFormat) {
    return outFormat == null || outFormat.toLowerCase(Locale.ROOT).equals("json");
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
    KeysetHandle handle = KeysetHandle.generateNew(keyTemplate);

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
      Parameters parameters)
      throws GeneralSecurityException, IOException {
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder(
            getKeysetHandle(inputStream, inFormat, masterKeyUri, credentialPath));
    switch (type) {
      case ADD_KEY:
        builder.addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId());
        break;
      case ROTATE_KEYSET:
        builder.addEntry(
            KeysetHandle.generateEntryFromParameters(parameters).withRandomId().makePrimary());
        break;
      default:
        throw new GeneralSecurityException("invalid command");
    }

    writeKeyset(builder.build(), outputStream, outFormat, masterKeyUri, credentialPath);
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
    if (masterKeyUri != null) {
      Aead masterKey =
          KmsClientsFactory.globalInstance()
              .newClientFor(masterKeyUri)
              .withCredentials(credentialPath)
              .getAead(masterKeyUri);
      if (isJson(outFormat)) {
        outputStream.write(
            TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(handle, masterKey, new byte[] {})
                .getBytes(UTF_8));
        return;
      } else {
        outputStream.write(
            TinkProtoKeysetFormat.serializeEncryptedKeyset(handle, masterKey, new byte[] {}));
        return;
      }
    }
    if (isJson(outFormat)) {
      outputStream.write(
          TinkJsonProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get())
              .getBytes(UTF_8));
      return;
    }
    outputStream.write(
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get()));
    return;
  }

  private static byte[] combine(ArrayDeque<byte[]> deque) {
    int totalSize = 0;
    for (byte[] buf : deque) {
      totalSize += buf.length;
    }
    byte[] result = new byte[totalSize];
    int curSize = 0;
    for (byte[] buf : deque) {
      System.arraycopy(buf, 0, result, curSize, buf.length);
      curSize += buf.length;
    }
    return result;
  }

  private static byte[] toByteArray(InputStream in) throws IOException {
    ArrayDeque<byte[]> deque = new ArrayDeque<>();
    byte[] buf = new byte[100];
    int read = in.read(buf);
    while (read != -1) {
      deque.add(Arrays.copyOf(buf, read));
      read = in.read(buf);
    }
    return combine(deque);
  }

  /**
   * Returns a {@code KeysetHandle} from either a cleartext {@code Keyset} or a {@code
   * EncryptedKeyset}, read from {@code inputStream}.
   */
  public static KeysetHandle getKeysetHandle(
      InputStream inputStream, String inFormat, String masterKeyUri, String credentialPath)
      throws IOException, GeneralSecurityException {
    byte[] keyset = toByteArray(inputStream);
    if (masterKeyUri != null) {
      Aead masterKey =
          KmsClientsFactory.globalInstance()
              .newClientFor(masterKeyUri)
              .withCredentials(credentialPath)
              .getAead(masterKeyUri);
      if (isJson(inFormat)) {
        return TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
            new String(keyset, UTF_8), masterKey, new byte[] {});
      } else {
        return TinkProtoKeysetFormat.parseEncryptedKeyset(keyset, masterKey, new byte[] {});
      }
    }
    if (isJson(inFormat)) {
      return TinkJsonProtoKeysetFormat.parseKeyset(
          new String(keyset, UTF_8), InsecureSecretKeyAccess.get());
    }
    return TinkProtoKeysetFormat.parseKeyset(keyset, InsecureSecretKeyAccess.get());
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
