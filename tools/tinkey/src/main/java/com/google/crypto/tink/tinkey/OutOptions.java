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

import java.io.IOException;
import java.io.OutputStream;
import org.kohsuke.args4j.Option;

/**
 * Common args for commands that write to file and need credential.
 */
class OutOptions extends InOptions {
  @Option(
      name = "--out",
      metaVar = "path/to/keyset.json",
      handler = OutputStreamHandler.class,
      required = false,
      usage = "The output filename, must not exist, to write the keyset to or "
          + "standard output if not specified")
  OutputStream outputStream;

  @Option(
      name = "--out-format",
      metaVar = "json | binary",
      required = false,
      usage = "The output format: json or binary (case-insensitive). json is default")
  String outFormat;

  @Override
  void validate() throws IOException {
    super.validate();
    if (outputStream == null) {
      outputStream = System.out;
    }
    TinkeyUtil.validateFormat(outFormat);
  }
}
