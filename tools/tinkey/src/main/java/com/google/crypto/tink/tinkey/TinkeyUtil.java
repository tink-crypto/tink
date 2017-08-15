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
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetReaders;
import com.google.crypto.tink.KeysetWriter;
import com.google.crypto.tink.KeysetWriters;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.TextFormatKeysetReaders;
import com.google.crypto.tink.TextFormatKeysetWriters;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import com.google.protobuf.Message.Builder;
import com.google.protobuf.TextFormat;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

/**
 * Various helpers.
 */
public class TinkeyUtil {
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
    SubtleUtil.validateTypeUrl(typeUrl);
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
   * Creates a {@code KeysetWriter} that can write the keyset in the right {@code outFormat}.
   */
  public static KeysetWriter createKeysetWriter(OutputStream outputStream, String outFormat)
      throws IOException {
    if (outFormat == null || outFormat.equals("TEXT")) {
      return TextFormatKeysetWriters.withOutputStream(outputStream);
    }
    return KeysetWriters.withOutputStream(outputStream);
  }

  /**
   * Writes {@code proto} in {@code outFormat} to {@code outputStream}.
   */
  public static void writeProto(Message proto, OutputStream outputStream, String outFormat)
      throws IOException {
    byte[] output;
    if (outFormat == null || outFormat.equals("TEXT")) {
      output = TextFormat.printToUnicodeString(proto).getBytes("UTF-8");
    } else {
      output = proto.toByteArray();
    }
    outputStream.write(output);
  }

  /**
   * Returns a {@code KeysetHandle} from either a cleartext {@code Keyset} or a
   * {@code EncryptedKeyset}, read from {@code inputStream}.
   */
  public static KeysetHandle getKeysetHandle(InputStream inputStream, String inFormat,
      File credentialFile) throws IOException, GeneralSecurityException {
    if (inFormat == null || inFormat.equals("TEXT")) {
      return CleartextKeysetHandle.read(
          TextFormatKeysetReaders.withInputStream(inputStream));
    }
    return CleartextKeysetHandle.read(
        KeysetReaders.withInputStream(inputStream));
    // TODO(thaidn): handle encrypted keysets.
  }

  /**
   * Checks that input or output format is valid. Only supported formats are TEXT and BINARY.
   * @throws IllegalArgumentException iff format is invalid.
   */
  public static void validateInputOutputFormat(String format) throws IllegalArgumentException {
    if (format != null
        && !format.equals("TEXT")
        && !format.equals("BINARY")) {
      throw new IllegalArgumentException("invalid format: " + format);
    }
  }
}
