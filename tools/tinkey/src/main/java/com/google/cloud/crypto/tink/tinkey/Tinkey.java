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

import com.google.cloud.crypto.tink.aead.AeadFactory;
import com.google.cloud.crypto.tink.hybrid.HybridDecryptFactory;
import com.google.cloud.crypto.tink.hybrid.HybridEncryptFactory;
import com.google.cloud.crypto.tink.mac.MacFactory;
import com.google.cloud.crypto.tink.signature.PublicKeySignFactory;
import com.google.cloud.crypto.tink.signature.PublicKeyVerifyFactory;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;

/**
 * Tinkey is a command-line tool to manage keys for Tink.
 */
public class Tinkey {
  public static void main(String[] args) throws Exception {
    AeadFactory.registerStandardKeyTypes();
    MacFactory.registerStandardKeyTypes();
    HybridDecryptFactory.registerStandardKeyTypes();
    HybridEncryptFactory.registerStandardKeyTypes();
    PublicKeySignFactory.registerStandardKeyTypes();
    PublicKeyVerifyFactory.registerStandardKeyTypes();

    TinkeyCommands commands = new TinkeyCommands();
    CmdLineParser parser = new CmdLineParser(commands);

    try {
      parser.parseArgument(args);
    } catch (CmdLineException e) {
      System.out.println(e);
      System.out.println();
      e.getParser().printUsage(System.out);
      System.exit(1);
    }
    commands.command.run();
  }
}
