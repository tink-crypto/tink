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

import com.google.crypto.tink.subtle.SubtleUtil;
import java.io.OutputStream;
import org.kohsuke.args4j.Option;

/**
 * Common args for commands that write to file and need credential.
 */
class OutOptions extends InOptions {
  @Option(
      name = "--out",
      handler = OutputStreamHandler.class,
      required = false,
      usage = "The output filename to write the keyset to or standard output if not specified")
  OutputStream outputStream;

  @Option(
      name = "--out-format",
      metaVar = "TEXT | BINARY",
      required = false,
      usage = "The output format: TEXT or BINARY (case-insensitive). TEXT is default")
  String outFormat;

  @Override
  void validate() {
    super.validate();
    if (outputStream == null) {
      outputStream = System.out;
    }
    try {
      TinkeyUtil.validateInputOutputFormat(outFormat);
    } catch (Exception e) {
      SubtleUtil.die(e.toString());
    }
  }
}
