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
import java.io.InputStream;
import org.kohsuke.args4j.Option;

/**
 * Common args for commands that read from file.
 */
class InOptions extends OutOptions {
  @Option(
      name = "--in",
      handler = InputStreamHandler.class,
      required = true,
      usage = "The input filename to read the keyset from or standard input if not specified")
  InputStream inputStream;

  @Option(
      name = "--inFormat",
      required = false,
      metaVar = "TEXT | JSON | BINARY",
      usage = "The input format: TEXT, JSON or BINARY. TEXT is default")
  String inFormat;

  @Override
  void validate() {
    super.validate();
    if (inputStream == null) {
      inputStream = System.in;
    }
    try {
      TinkeyUtil.validateInputOutputFormat(inFormat);
    } catch (Exception e) {
      SubtleUtil.die(e.toString());
    }
  }
}
