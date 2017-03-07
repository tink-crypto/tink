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

import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import java.io.OutputStream;
import org.kohsuke.args4j.Option;

/**
 * Options for creating key templates.
 */
class CreateKeyTemplateOptions {
  @Option(
      name = "--type-url",
      metaVar = "type.googleapis.com/google.cloud.crypto.tink.AesGcmKey",
      required = true,
      usage = "The type URL of the key template")
  String typeUrlValue;

  @Option(
      name = "--key-format",
      metaVar = "\"key_size: 32\"",
      required = true,
      usage = "The key format of the key template, formatted as text proto")
  String keyFormatValue;

  @Option(
      name = "--out",
      handler = OutputStreamHandler.class,
      required = false,
      usage = "The output filename to write the key template to")
  OutputStream outputStream;

  void validate() {
    if (outputStream == null) {
      outputStream = System.out;
    }
    try {
      SubtleUtil.validate(typeUrlValue);
    } catch (Exception e) {
      SubtleUtil.die(e.toString());
    }
  }
}
