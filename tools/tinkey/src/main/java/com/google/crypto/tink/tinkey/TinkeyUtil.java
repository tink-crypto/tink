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

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.api.services.cloudkms.v1.CloudKMSScopes;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.ByteStreams;
import com.google.common.reflect.ClassPath;
import com.google.common.reflect.ClassPath.ClassInfo;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.GcpKmsAeadKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import com.google.protobuf.Message.Builder;
import com.google.protobuf.TextFormat;
import java.io.ByteArrayInputStream;
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
      String keyFormatName = SubtleUtil.getProtoClassName(typeUrl) + KEY_FORMAT_SUFFIX;
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
    Registry.INSTANCE.newKey(template);
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
   * @return a {@code KeyData} from a specified key.
   */
  public static KeyData createKeyData(Message key, String typeUrl, KeyData.KeyMaterialType type)
      throws Exception {
    return KeyData.newBuilder()
        .setValue(key.toByteString())
        .setTypeUrl(typeUrl)
        .setKeyMaterialType(type)
        .build();
  }

  /**
   * @return a {@code KeyData} containing a {@code GcpKmsAeadKey}.
   */
  public static KeyData createGcpKmsAeadKeyData(String kmsKeyUri)
      throws Exception {
    GcpKmsAeadKey keyProto = GcpKmsAeadKey.newBuilder()
        .setKmsKeyUri(kmsKeyUri)
        .build();
    return createKeyData(
        keyProto,
        "type.googleapis.com/google.crypto.tink.GcpKmsAeadKey",
        KeyData.KeyMaterialType.REMOTE);
  }

  /**
   * @return a {@code GoogleCredential}, using the service account in {@code credentialFile}.
   * If {@code credentialFile} is null, returns an
   * <a href="https://g.co/dv/identity/protocols/application-default-credentials">application
   * default credential</a>.
   */
  public static GoogleCredential readGoogleCredential(File credentialFile) throws IOException {
    GoogleCredential cred;
    if (credentialFile != null) {
      byte[] credBytes = Files.readAllBytes(credentialFile.toPath());
      cred = GoogleCredential.fromStream(new ByteArrayInputStream(credBytes));
    } else {
      cred = GoogleCredential.getApplicationDefault();
    }
    // Depending on the environment that provides the default credentials (e.g. Compute Engine, App
    // Engine), the credentials may require us to specify the scopes we need explicitly.
    // Check for this case, and inject the scope if required.
    if (cred.createScopedRequired()) {
      cred = cred.createScoped(CloudKMSScopes.all());
    }
    return cred;
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
   * Writes {@code proto} in {@code outFormat} to {@code outputStream}. Closes
   * {@code outputStream} afterward.
   */
  public static void writeProto(Message proto, OutputStream outputStream, String outFormat)
      throws IOException {
    byte[] output;
    if (outFormat == null || outFormat.equals("TEXT")) {
      output = TextFormat.printToUnicodeString(proto).getBytes("UTF-8");
    } else {
      output = proto.toByteArray();
    }
    try {
      outputStream.write(output);
    } finally {
      outputStream.close();
    }
  }

  /**
   * Returns a {@code KeysetHandle} from either a cleartext {@code Keyset} or a
   * {@code EncryptedKeyset}, read from {@code inputStream}.
   * Closes {code inputStream} afterward.
   */
  public static KeysetHandle getKeysetHandle(InputStream inputStream, String inFormat,
      File credentialFile) throws IOException, GeneralSecurityException {
    byte[] inBytes = ByteStreams.toByteArray(inputStream);
    inputStream.close();
    if (inFormat == null || inFormat.equals("TEXT")) {
      Keyset.Builder builder = Keyset.newBuilder();
      TextFormat.merge(new String(inBytes, "UTF-8"), builder);
      return CleartextKeysetHandle.parseFrom(builder.build());
    }
    return CleartextKeysetHandle.parseFrom(inBytes);
  }

  /**
   * @return a {@code CloudKMS}, using the service account in {@code credentialFile}.
   * If {@code credentialFile} is null, doesn't exist or doesn't contain a valid service
   * account, uses an
   * <a href="https://g.co/dv/identity/protocols/application-default-credentials">application
   * default credential</a>.
   */
  public static CloudKMS createCloudKmsClient(File credentialFile) throws IOException {
    HttpTransport transport = new NetHttpTransport();
    JsonFactory jsonFactory = new JacksonFactory();
    return new CloudKMS.Builder(transport, jsonFactory, readGoogleCredential(credentialFile))
        .setApplicationName("Tinkey")
        .build();
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
