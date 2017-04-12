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

package com.google.cloud.crypto.tink.tinkey;

import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.KeysetManager;
import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.KmsEncryptedKeyset;
import com.google.cloud.crypto.tink.subtle.GcpKmsAead;
import com.google.protobuf.Message;
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
  }

  /**
   * Creates a keyset that contains a single key of template {@code keyTemplate}, and writes it
   * to {@code outputStream}. Attempts to encrypt the keyset using {@code credentialFile} and either
   * {@code gcpKmsMasterKeyValue} or {@code awsKmsMasterKeyUriValue}.
   */
  public static void create(OutputStream outputStream, String outFormat, File credentialFile,
      KeyTemplate keyTemplate, String gcpKmsMasterKeyUriValue, String awsKmsMasterKeyUriValue)
      throws Exception {
    Message keyset;
    if (gcpKmsMasterKeyUriValue != null) {
      keyset = createEncryptedKeysetWithGcp(credentialFile, keyTemplate,
          gcpKmsMasterKeyUriValue);
    } else if (awsKmsMasterKeyUriValue != null) {
      keyset = createEncryptedKeysetWithAws(credentialFile, keyTemplate,
          awsKmsMasterKeyUriValue);
    } else {
      // cleartext, empty, keyset.
      keyset = createCleartextKeyset(keyTemplate);
    }
    TinkeyUtil.writeProto(keyset, outFormat, outputStream);
  }

  /**
   * Creates a keyset that contains a single key of template {@code keyTemplateFile}.
   * @return the resulting keyset.
   */
  public static final Keyset createCleartextKeyset(KeyTemplate keyTemplate) throws Exception {
    KeysetManager manager = new KeysetManager.Builder()
        .setKeyTemplate(keyTemplate)
        .build()
        .rotate();
    return manager.getKeysetHandle().getKeyset();
  }

  /**
   * Creates a keyset that contains a single key of template {@code keyTemplateFile}.
   * Encrypts the keyset using {@code credentialFile} and {@code gcpKmsMasterKeyUriValue}.
   * @return the resulting encrypted keyset.
   * @throws GeneralSecurityException if failed to encrypt keyset.
   */
  public static final KmsEncryptedKeyset createEncryptedKeysetWithGcp(
      File credentialFile, KeyTemplate keyTemplate,
      String gcpKmsMasterKeyUriValue) throws Exception {
    KeysetManager manager = new KeysetManager.Builder()
        .setKeyTemplate(keyTemplate)
        .build()
        .rotate();
    GcpKmsAead aead = new GcpKmsAead(
        TinkeyUtil.createCloudKmsClient(credentialFile), gcpKmsMasterKeyUriValue);
    KeysetHandle handle = manager.getKeysetHandle(aead);
    return TinkeyUtil.createKmsEncryptedKeyset(
        TinkeyUtil.createGcpKmsAeadKeyData(gcpKmsMasterKeyUriValue),
        handle);
  }

  /**
   * Creates a keyset that contains a single key of template {@code keyTemplate}.
   * Encrypts the keyset using {@code credentialFile} and {@code awsKmsMasterKeyUriValue}.
   * @return the resulting keyset in text format.
   * @throws GeneralSecurityException if failed to encrypt keyset.
   */
  public static final KmsEncryptedKeyset createEncryptedKeysetWithAws(
      File credentialFile, KeyTemplate keyTemplate,
      String awsKmsMasterKeyUriValue) throws Exception {
    throw new Exception("Not Implemented Yet");
  }
}
