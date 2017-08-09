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
import com.google.crypto.tink.KeysetManager;
import com.google.crypto.tink.KeysetWriter;
import com.google.crypto.tink.integration.GcpKmsAead;
import com.google.crypto.tink.integration.GcpKmsClient;
import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.KeyTemplate;
import java.io.File;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/**
 * Creates a new keyset.
 */
public class CreateCommand extends CreateOptions implements Command {
  @Override
  public void run() throws Exception {
    validate();
    create(outputStream, outFormat, credentialFile, keyTemplate,
        gcpKmsMasterKeyUriValue, awsKmsMasterKeyUriValue);
    outputStream.close();
  }

  /**
   * Creates a keyset that contains a single key of template {@code keyTemplate}, and writes it
   * to {@code outputStream}. Attempts to encrypt the keyset using {@code credentialFile} and either
   * {@code gcpKmsMasterKeyValue} or {@code awsKmsMasterKeyUriValue}.
   */
  public static void create(OutputStream outputStream, String outFormat, File credentialFile,
      KeyTemplate keyTemplate, String gcpKmsMasterKeyUriValue, String awsKmsMasterKeyUriValue)
      throws Exception {
    KeysetWriter writer = TinkeyUtil.createKeysetWriter(outputStream, outFormat);
    if (gcpKmsMasterKeyUriValue != null) {
      createEncryptedKeysetWithGcp(credentialFile, keyTemplate, gcpKmsMasterKeyUriValue, writer);
    } else if (awsKmsMasterKeyUriValue != null) {
      createEncryptedKeysetWithAws(credentialFile, keyTemplate, awsKmsMasterKeyUriValue, writer);
    } else {
      // cleartext, empty, keyset.
      createCleartextKeyset(keyTemplate, writer);
    }
  }

  /**
   * Creates a keyset that contains a single key of template {@code keyTemplateFile}.
   */
  public static final void createCleartextKeyset(KeyTemplate keyTemplate, KeysetWriter writer)
      throws Exception {
    KeysetManager
        .withEmptyKeyset()
        .rotate(keyTemplate)
        .getKeysetHandle()
        .write(writer);
  }

  /**
   * Creates a keyset that contains a single key of template {@code keyTemplateFile}.
   * Encrypts the keyset using {@code credentialFile} and {@code gcpKmsMasterKeyUriValue}.
   * @throws GeneralSecurityException if failed to encrypt keyset.
   */
  public static final void createEncryptedKeysetWithGcp(
      File credentialFile, KeyTemplate keyTemplate,
      String gcpKmsMasterKeyUriValue, KeysetWriter writer) throws Exception {
    Aead masterKey = new GcpKmsAead(
        GcpKmsClient.fromNullableServiceAccount(credentialFile),
        gcpKmsMasterKeyUriValue);
    KeysetManager
        .withEmptyKeyset()
        .rotate(keyTemplate)
        .getKeysetHandle()
        .writeEncrypted(writer, masterKey);
  }

  /**
   * Creates a keyset that contains a single key of template {@code keyTemplate}.
   * Encrypts the keyset using {@code credentialFile} and {@code awsKmsMasterKeyUriValue}.
   * @return the resulting keyset in text format.
   * @throws GeneralSecurityException if failed to encrypt keyset.
   */
  public static final EncryptedKeyset createEncryptedKeysetWithAws(
      File credentialFile, KeyTemplate keyTemplate,
      String awsKmsMasterKeyUriValue, KeysetWriter writer) throws Exception {
    throw new Exception("Not Implemented Yet");
  }
}
