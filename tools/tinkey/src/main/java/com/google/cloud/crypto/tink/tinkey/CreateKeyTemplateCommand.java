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

import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import java.io.OutputStream;

/**
 * Creates a new {@code KeyTemplate}.
 */
public class CreateKeyTemplateCommand extends CreateKeyTemplateOptions implements Command {
  @Override
  public void run() throws Exception {
    validate();
    create(outputStream, typeUrlValue, keyFormatValue);
  }

  /**
   * Creates a {@code KeyTemplate} containing a key of type {@code typeUrlValue} and
   * {@code keyFormatValue}.
   */
  public static void create(OutputStream outputStream, String typeUrlValue,
      String keyFormatValue) throws Exception {
    KeyTemplate keyTemplate = TinkeyUtil.createKeyTemplateFromText(typeUrlValue, keyFormatValue);
    String comment = "# Format: https://github.com/google/tink/blob/master/proto/tink.proto#L52\n"
        + "# Generated with command:\n"
        + "#     tinkey create-key-template \\\n"
        + String.format("#     --type-url %s \\\n", typeUrlValue)
        + String.format("#     --key-format \"%s\"\n", keyFormatValue);
    outputStream.write(comment.getBytes("UTF-8"));
    TinkeyUtil.writeProto(keyTemplate, "TEXT" /* outFormat */, outputStream);
  }
}
