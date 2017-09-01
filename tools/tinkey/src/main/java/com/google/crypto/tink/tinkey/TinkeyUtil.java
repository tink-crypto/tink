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

import com.google.common.collect.ImmutableSet;
import com.google.common.reflect.ClassPath;
import com.google.common.reflect.ClassPath.ClassInfo;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.BinaryKeysetWriter;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetManager;
import com.google.crypto.tink.KeysetReader;
import com.google.crypto.tink.KeysetWriter;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.Message.Builder;
import com.google.protobuf.TextFormat;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

/**
 * Various helpers.
 */
class TinkeyUtil {
  public enum CommandType {
    ADD_KEY,
    CONVERT_KEYSET,
    CREATE_KEYSET,
    CREATE_PUBLIC_KEYSET,
    CREATE_KEY_TEMPLATE,
    DELETE_KEY,
    DESTROY_KEY,
    DISABLE_KEY,
    ENABLE_KEY,
    LIST_KEYSET,
    ROTATE_KEYSET,
    PROMOTE_KEY
  };

  /**
   * By convention, the key format proto of XyzKey would be XyzKeyFormat.
   * For example, the key format proto of AesGcmKey is AesGcmKeyFormat.
   */
  public static final String KEY_FORMAT_SUFFIX = "Format";

  /**
   * By convention, the key format proto of XyzPrivateKey would be XyzKeyFormat.
   * For example, the key format proto of EcdsaPrivateKey is EcdsaKeyFormat, i.e.,
   * the string "Private" has to be removed from the name.
   */
  public static final String PRIVATE = "Private";

  /**
   * @return a {@code KeyTemplate} for {@code typeUrl} and {@code keyFormat}. For example,
   * createKeyTemplateFromText(
   *    "type.googleapis.com/google.crypto.tink.AesGcmKey",
   *    "key_size: 32")
   * would return a {@code KeyTemplate} for 256-bit AES-GCM.
   *
   * @throws IllegalArgumentException if either {@code typeUrl} or {@keyFormat} is invalid.
   */
  public static KeyTemplate createKeyTemplateFromText(String typeUrl, String keyFormat)
      throws IllegalArgumentException {
    try {
      // To parse {@code keyFormat}, we need to find the corresponding proto class.
      String keyFormatName = getProtoClassName(typeUrl) + KEY_FORMAT_SUFFIX;
      keyFormatName = keyFormatName.replace(PRIVATE, "");
      Class<?> keyFormatClass = loadClass(keyFormatName);
      Builder builder = getBuilder(keyFormatClass);
      TextFormat.merge(keyFormat, builder);
      return createKeyTemplateFromBinary(typeUrl, builder.build().toByteString());
    } catch (Exception e) {
      throw new IllegalArgumentException("invalid type URL or key format", e);
    }
  }

  /**
   * @return a {@code KeyTemplate} constructed from {@code typeUrl} and {@code format}.
   * @throws {@code GeneralSecurityException} if invalid {@code format} or {@code typeUrl}.
   */
  private static KeyTemplate createKeyTemplateFromBinary(String typeUrl, ByteString format)
      throws GeneralSecurityException {
    KeyTemplate template = KeyTemplate.newBuilder()
        .setTypeUrl(typeUrl)
        .setValue(format)
        .build();
    // Tests whether the key template works.
    Registry.newKey(template);
    return template;
  }

  /**
   * @return a {@code Builder} of {@code messageClass} which is a protobuf message.
   */
  private static Builder getBuilder(Class<?> messageClass) throws Exception {
    return (Builder) messageClass
        .getDeclaredMethod("newBuilder")
        .invoke(null /* Object, ignored */);
  }

  /**
   * Finds and loads {@code className}.
   */
  private static Class<?> loadClass(String className) throws IOException {
    ImmutableSet<ClassInfo> classInfos =
        ClassPath.from(TinkeyUtil.class.getClassLoader()).getAllClasses();
    for (ClassInfo classInfo : classInfos) {
      if (classInfo.getName().toLowerCase().endsWith(className.toLowerCase())) {
        return classInfo.load();
      }
    }
    throw new IOException("class not found: " + className);
  }

  /**
   * @return the class name of a proto from its type url. For example, return AesGcmKey
   * if the type url is type.googleapis.com/google.crypto.tink.AesGcmKey.
   * @throws GeneralSecurityException if {@code typeUrl} is in invalid format.
   */
  private static String getProtoClassName(String typeUrl) throws GeneralSecurityException {
    Validators.validateTypeUrl(typeUrl);
    int dot = typeUrl.lastIndexOf(".");
    return typeUrl.substring(dot + 1);
  }

  /**
   * @return a {@code KeyTemplate} in {@code keyTemplatePath}.
   */
  public static KeyTemplate readKeyTemplateFromTextFile(Path keyTemplatePath) throws IOException {
    byte[] templateBytes = Files.readAllBytes(keyTemplatePath);
    KeyTemplate.Builder builder = KeyTemplate.newBuilder();
    TextFormat.merge(new String(templateBytes, "UTF-8"), builder);
    return builder.build();
  }

  /**
   * Creates a {@code KeysetReader} that can read the keyset in the right {@code inFormat}.
   */
  public static KeysetReader createKeysetReader(InputStream inputStream, String inFormat)
      throws IOException {
    if (inFormat == null || inFormat.toLowerCase().equals("json")) {
      return JsonKeysetReader.withInputStream(inputStream);
    }
    return BinaryKeysetReader.withInputStream(inputStream);
  }

  /**
   * Creates a {@code KeysetWriter} that can write the keyset in the right {@code outFormat}.
   */
  public static KeysetWriter createKeysetWriter(OutputStream outputStream, String outFormat)
      throws IOException {
    if (outFormat == null || outFormat.toLowerCase().equals("json")) {
      return JsonKeysetWriter.withOutputStream(outputStream);
    }
    return BinaryKeysetWriter.withOutputStream(outputStream);
  }

  /**
   * Creates a keyset that contains a single key of template {@code keyTemplate}, encrypts it
   * using {@code credentialPath} and {@code masterKeyUri}, then encodes it in {@code outFormat}.
   * @return an input stream containing the resulting encrypted keyset.
   * @throws GeneralSecurityException if failed to encrypt keyset.
   */
  public static final InputStream createKeyset(KeyTemplate keyTemplate,
      String outFormat, String masterKeyUri, String credentialPath)
      throws GeneralSecurityException, IOException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    createKeyset(outputStream, outFormat, masterKeyUri, credentialPath, keyTemplate);
    return new ByteArrayInputStream(outputStream.toByteArray());
  }

  /**
   * Creates a keyset that contains a single key of template {@code keyTemplate}, encrypts it
   * using {@code credentialPath} and {@code masterKeyUri}, then writes it to {@code writer}.
   */
  public static void createKeyset(
      OutputStream outputStream, String outFormat,
      String masterKeyUri, String credentialPath, KeyTemplate keyTemplate)
        throws GeneralSecurityException, IOException {
    KeysetHandle handle = KeysetManager
        .withEmptyKeyset()
        .rotate(keyTemplate)
        .getKeysetHandle();

    writeKeyset(handle, outputStream, outFormat, masterKeyUri, credentialPath);
  }

  /**
   * Manipulates a key within a keyset.
   */
  public static void manipulateKey(
      CommandType type, OutputStream outputStream,
      String outFormat, InputStream inputStream, String inFormat, String masterKeyUri,
      String credentialPath, int keyId) throws GeneralSecurityException, IOException {
    KeysetManager manager = KeysetManager.withKeysetHandle(
        getKeysetHandle(inputStream, inFormat, masterKeyUri, credentialPath));
    switch (type) {
        case DELETE_KEY:
            manager = manager.delete(keyId);
            break;
        case DESTROY_KEY:
            manager = manager.destroy(keyId);
            break;
        case DISABLE_KEY:
            manager = manager.enable(keyId);
            break;
        case ENABLE_KEY:
            manager = manager.enable(keyId);
            break;
        case PROMOTE_KEY:
            manager = manager.promote(keyId);
            break;
        default:
            throw new GeneralSecurityException("invalid command");
    }

    writeKeyset(manager.getKeysetHandle(), outputStream, outFormat, masterKeyUri, credentialPath);
  }

  /**
   * Creates and adds a new key to an existing keyset.
   * The new key becomes the primary key if {@code type} is {@link CommandType#ROTATE}.
   */
  public static void createKey(
      CommandType type, OutputStream outputStream, String outFormat, InputStream inputStream,
      String inFormat, String masterKeyUri, String credentialPath,
      KeyTemplate keyTemplate) throws GeneralSecurityException, IOException {
    KeysetManager manager = KeysetManager.withKeysetHandle(
        getKeysetHandle(inputStream, inFormat, masterKeyUri, credentialPath));
    switch (type) {
        case ADD_KEY:
            manager = manager.add(keyTemplate);
            break;
        case ROTATE_KEYSET:
            manager = manager.rotate(keyTemplate);
            break;
        default:
            throw new GeneralSecurityException("invalid command");
    }

    writeKeyset(manager.getKeysetHandle(), outputStream, outFormat, masterKeyUri, credentialPath);
  }

  /**
   * Writes the keyset managed by {@code handle} to {@code outputStream} with format
   * {@code outFormat}. Maybe encrypt it with {@code masterKeyUri} and {@code credentialPath}.
   */
  public static void writeKeyset(KeysetHandle handle, OutputStream outputStream,
      String outFormat, String masterKeyUri, String credentialPath)
      throws GeneralSecurityException, IOException {
    KeysetWriter writer = createKeysetWriter(outputStream, outFormat);
    if (masterKeyUri != null) {
      Aead masterKey = KmsClients.getAutoLoaded(masterKeyUri)
          .withCredentials(credentialPath)
          .getAead(masterKeyUri);
      handle.write(writer, masterKey);
    } else {
      CleartextKeysetHandle.write(handle, writer);
    }
  }

  /**
   * Manipulates a keyset
   */
  public static void manipulateEncryptedKeyset(
      CommandType type, OutputStream outputStream,
      String outFormat, InputStream inputStream, String inFormat, String masterKeyUri,
      String credentialPath, String keyId) throws GeneralSecurityException, IOException {

  }

  /**
   * Returns a {@code KeysetHandle} from either a cleartext {@code Keyset} or a
   * {@code EncryptedKeyset}, read from {@code inputStream}.
   */
  public static KeysetHandle getKeysetHandle(InputStream inputStream, String inFormat,
      String masterKeyUri, String credentialPath) throws IOException, GeneralSecurityException {
    KeysetReader reader = createKeysetReader(inputStream, inFormat);
    KeysetHandle handle;
    if (masterKeyUri != null) {
      Aead masterKey = KmsClients.getAutoLoaded(masterKeyUri)
          .withCredentials(credentialPath)
          .getAead(masterKeyUri);
      return KeysetHandle.read(reader, masterKey);
    }
    return CleartextKeysetHandle.read(reader);
  }

  /**
   * Checks that input or output format is valid. Only supported formats are {@code json} and
   * {@code binary} (case-insensitive).
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

  /**
   * Prints an error then exits.
   */
  public static void die(String error) {
    System.err.print(String.format("Error: %s\n", error));
    System.exit(1);
  }
}
