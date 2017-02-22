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

import org.kohsuke.args4j.Option;

/**
 * Common args for commands that write to file and need credential.
 */
class OutOptions {
  @Option(name = "--out", required = true, usage = "The output filename to write the keyset to")
  String outFilename;

  @Option(name = "--credential", required = false,
      usage = "The filename with credential to use the master key")
  String credentialFilename;
}
