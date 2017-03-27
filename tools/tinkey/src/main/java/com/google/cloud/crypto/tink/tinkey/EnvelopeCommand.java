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

import com.google.cloud.crypto.tink.KeysetManager;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.protobuf.TextFormat;
import java.io.FileOutputStream;

/**
 * Creates a keyset containing an envelope encryption key.
 */
public class EnvelopeCommand extends EnvelopeOptions implements Command {
  private static final String KMS_ENVELOPE_AEAD_KEY_TYPE =
      "type.googleapis.com/google.cloud.crypto.tink.KmsEnvelopeAeadKey";

  @Override
  public void run() throws Exception {
    Keyset keyset = createKeyset(dekTypeValue, dekFormatValue, kmsKeyUriValue);
    FileOutputStream stream = new FileOutputStream(outFilename);
    try {
      stream.write(TextFormat.printToUnicodeString(keyset).getBytes("UTF-8"));
    } finally {
      stream.close();
    }
  }

  /**
   * @return a keyset containing a {@code KmsEnvelopeAeadKey}, using
   * {@code dekTypeValue} and {@code dekFormatValue} to construct DEK format,
   * and using {@code kmsKeyUriValue} to construct the KMS key.
   */
  public static Keyset createKeyset(String dekTypeValue, String dekFormatValue,
      String kmsKeyUriValue) throws Exception {
    KeyData kmsKey = Util.createGoogleCloudKmsAeadKeyData(kmsKeyUriValue);
    KeyTemplate dekTemplate = Util.createKeyTemplate(dekTypeValue, dekFormatValue);
    KeyTemplate keyTemplate = Util.createKeyTemplate(
        KMS_ENVELOPE_AEAD_KEY_TYPE,
        Util.createKmsEnvelopeAeadKeyFormat(kmsKey, dekTemplate).toByteString());
    KeysetManager manager = new KeysetManager.Builder()
        .setKeyTemplate(keyTemplate)
        .build()
        .rotate();
    return manager.getKeysetHandle().getKeyset();
  }
}